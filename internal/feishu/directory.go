//lint:file-ignore ST1005 Feishu API errors intentionally retain the product's official capitalization.
package feishu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/xxvcc/security-update-notify/internal/httpx"
)

const (
	maxDirectoryRespBytes = 4 << 20
	maxDirectoryUsers     = 10000
	maxDirectoryPages     = 1000
	maxPageTokenBytes     = 4096
)

// DirectoryUser is the stable tuple shown during interactive recipient selection. Name and MobileTail are
// human verification hints; OpenID is the app-scoped identifier persisted for delivery.
type DirectoryUser struct {
	Name       string
	MobileTail string
	OpenID     string
}

type directoryResponse struct {
	Code *int `json:"code"`
	Data struct {
		Employees []struct {
			BaseInfo struct {
				EmployeeID string `json:"employee_id"`
				Mobile     string `json:"mobile"`
				Name       struct {
					Name struct {
						I18NValue    map[string]string `json:"i18n_value"`
						DefaultValue string            `json:"default_value"`
					} `json:"name"`
				} `json:"name"`
			} `json:"base_info"`
		} `json:"employees"`
		Abnormals    json.RawMessage `json:"abnormals"`
		PageResponse struct {
			HasMore   *bool  `json:"has_more"`
			PageToken string `json:"page_token"`
		} `json:"page_response"`
	} `json:"data"`
}

// ScanDirectory lists every visible active employee under Feishu's root department. It uses Directory v1,
// requests open_id explicitly, rejects partial responses, and bounds pages, users, tokens, and response sizes.
func (c *Client) ScanDirectory(ctx context.Context, appID, appSecret string) ([]DirectoryUser, error) {
	if err := validateCredentials(appID, appSecret); err != nil {
		return nil, err
	}
	base := c.base()
	if err := httpx.GuardAPIBase(base); err != nil {
		return nil, err
	}
	token, err := c.tenantToken(ctx, appID, appSecret)
	if err != nil {
		return nil, err
	}

	users := make([]DirectoryUser, 0)
	seenIDs := make(map[string]struct{})
	seenPageTokens := make(map[string]struct{})
	pageToken := ""
	for page := 0; page < maxDirectoryPages; page++ {
		resp, err := c.directoryPage(ctx, base, token, pageToken)
		if err != nil {
			return nil, err
		}
		if resp.Code == nil || *resp.Code != 0 {
			code := "missing"
			if resp.Code != nil {
				code = fmt.Sprint(*resp.Code)
			}
			return nil, fmt.Errorf("Feishu directory scan failed: code=%s", code)
		}
		if rawJSONNonEmpty(resp.Data.Abnormals) {
			return nil, fmt.Errorf("Feishu directory scan incomplete: abnormals returned")
		}
		if resp.Data.PageResponse.HasMore == nil {
			return nil, fmt.Errorf("Feishu directory scan incomplete: page_response.has_more missing")
		}
		for _, employee := range resp.Data.Employees {
			openID := employee.BaseInfo.EmployeeID
			if len(openID) > 256 || !openIDPattern.MatchString(openID) {
				continue
			}
			if _, duplicate := seenIDs[openID]; duplicate {
				continue
			}
			seenIDs[openID] = struct{}{}
			if len(users) >= maxDirectoryUsers {
				return nil, fmt.Errorf("Feishu directory exceeds %d visible users", maxDirectoryUsers)
			}
			name := employee.BaseInfo.Name.Name.I18NValue["zh_cn"]
			if name == "" {
				name = employee.BaseInfo.Name.Name.DefaultValue
			}
			users = append(users, DirectoryUser{
				Name:       truncateRunes(sanitizeDisplayHint(name), 256),
				MobileTail: lastRunes(sanitizeDisplayHint(employee.BaseInfo.Mobile), 4),
				OpenID:     openID,
			})
		}

		hasMore := *resp.Data.PageResponse.HasMore
		nextToken := resp.Data.PageResponse.PageToken
		if len(nextToken) > maxPageTokenBytes {
			return nil, fmt.Errorf("Feishu directory returned an oversized page token")
		}
		// Some final Feishu pages retain the previous page token. has_more=false is authoritative and must be
		// checked before duplicate-token detection, otherwise a complete scan is falsely rejected.
		if !hasMore {
			return users, nil
		}
		if nextToken == "" {
			return nil, fmt.Errorf("Feishu directory pagination indicated more results without a page token")
		}
		if _, duplicate := seenPageTokens[nextToken]; duplicate {
			return nil, fmt.Errorf("Feishu directory pagination repeated a page token")
		}
		seenPageTokens[nextToken] = struct{}{}
		pageToken = nextToken
	}
	return nil, fmt.Errorf("Feishu directory pagination exceeded %d pages", maxDirectoryPages)
}

func (c *Client) directoryPage(ctx context.Context, base, token, pageToken string) (directoryResponse, error) {
	pageRequest := map[string]any{"page_size": 100}
	if pageToken != "" {
		pageRequest["page_token"] = pageToken
	}
	payload := map[string]any{
		"filter": map[string]any{"conditions": []map[string]string{
			{"field": "base_info.departments.department_id", "operator": "eq", "value": `"0"`},
			{"field": "work_info.staff_status", "operator": "eq", "value": "1"},
		}},
		"required_fields": []string{"base_info.employee_id", "base_info.name", "base_info.mobile"},
		"page_request":    pageRequest,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return directoryResponse{}, err
	}
	endpoint := base + "/open-apis/directory/v1/employees/filter?employee_id_type=open_id&department_id_type=open_department_id"
	client, err := httpx.NoRedirects(c.HTTP)
	if err != nil {
		return directoryResponse{}, err
	}
	var result directoryResponse
	err = c.retry(ctx, func() (bool, time.Duration, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return false, 0, err
		}
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return true, 0, sanitizeExternalError("Feishu directory request failed", err, token)
		}
		defer resp.Body.Close()
		respBody, err := readDirectoryBody(resp.Body)
		if err != nil {
			// Directory filtering is read-only, so interrupted reads are safe to retry.
			return !errors.Is(err, errDirectoryResponseTooLarge), 0, temporary(err)
		}
		if retryableStatus(resp.StatusCode) {
			return true, retryAfter(resp), fmt.Errorf("Feishu directory HTTP %d", resp.StatusCode)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return false, 0, fmt.Errorf("Feishu directory HTTP %d", resp.StatusCode)
		}
		var decoded directoryResponse
		if err := json.Unmarshal(respBody, &decoded); err != nil {
			return false, 0, temporary(fmt.Errorf("invalid Feishu directory response"))
		}
		apiRateLimited := decoded.Code != nil && *decoded.Code == apiRateLimitCode
		if apiRateLimited {
			return true, retryAfter(resp), fmt.Errorf("Feishu directory temporarily unavailable")
		}
		result = decoded
		return false, 0, nil
	})
	return result, err
}

func readDirectoryBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxDirectoryRespBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read Feishu directory response")
	}
	if len(body) > maxDirectoryRespBytes {
		return nil, errDirectoryResponseTooLarge
	}
	return body, nil
}

func rawJSONNonEmpty(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "null" && s != "[]" && s != "{}"
}

// Directory names and phone hints are printed in a privileged interactive
// terminal. Remove terminal controls and Unicode formatting controls before
// they cross that display boundary while retaining ordinary international text.
func sanitizeDisplayHint(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return -1
		}
		return r
	}, value)
}

func truncateRunes(value string, max int) string {
	r := []rune(value)
	if len(r) > max {
		r = r[:max]
	}
	return string(r)
}

func lastRunes(value string, count int) string {
	r := []rune(value)
	if len(r) > count {
		r = r[len(r)-count:]
	}
	return string(r)
}
