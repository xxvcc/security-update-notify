#!/usr/bin/env bash
# Deterministic Fedora DNF5 versionlock regression. The fixture builds a local
# security update so the gate never depends on a floating image having updates.
set -euo pipefail

[[ -f /.dockerenv && "${SUN_CONTAINER_TEST:-0}" == 1 ]] || {
  echo "build/dnf5-versionlock-test.sh must run only in a disposable container" >&2
  exit 2
}
awk '$5 == "/src" && $6 ~ /(^|,)ro(,|$)/ { found = 1 } END { exit !found }' /proc/self/mountinfo || {
  echo "build/dnf5-versionlock-test.sh requires /src to be mounted read-only" >&2
  exit 2
}

# /etc/os-release is provided by every supported container image.
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == fedora && "${VERSION_ID:-}" =~ ^(43|44)$ ]] || {
  echo "DNF5 versionlock fixture requires Fedora 43 or 44" >&2
  exit 2
}
dnf_version="$(dnf --version)"
grep -Fq 'dnf5 version' <<<"$dnf_version"

work="$(mktemp -d)"
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT

dnf -y -q install rpm-build createrepo_c >/dev/null 2>&1

top="$work/rpmbuild"
mkdir -p "$top"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
cat >"$top/SPECS/sun-versionlock-fixture.spec" <<'EOF'
Name: sun-versionlock-fixture
Version: %{fixture_version}
Release: 1
Summary: Deterministic SUN DNF5 versionlock fixture
License: MIT
BuildArch: noarch

%description
Disposable package used only by the security-update-notify container gate.

%install
mkdir -p %{buildroot}/usr/share/sun-versionlock-fixture
printf '%s\n' '%{fixture_version}' >%{buildroot}/usr/share/sun-versionlock-fixture/version

%files
/usr/share/sun-versionlock-fixture/version
EOF

build_fixture() {
  local version="$1"
  rpmbuild -bb \
    --define "_topdir $top" \
    --define "fixture_version $version" \
    "$top/SPECS/sun-versionlock-fixture.spec" >/dev/null 2>&1
}

build_fixture 1.0
old_rpm="$top/RPMS/noarch/sun-versionlock-fixture-1.0-1.noarch.rpm"
rpm -i "$old_rpm"

build_fixture 2.0
new_name=sun-versionlock-fixture-2.0-1.noarch.rpm
new_rpm="$top/RPMS/noarch/$new_name"
repo="$work/repo"
reposdir="$work/repos.d"
mkdir -p "$repo" "$reposdir"
cp "$new_rpm" "$repo/$new_name"
createrepo_c "$repo" >/dev/null
fixture_sha="$(sha256sum "$repo/$new_name" | awk '{print $1}')"
cat >"$work/updateinfo.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<updates>
  <update from="security-update-notify" status="stable" type="security" version="1">
    <id>SUN-2026:0001</id>
    <title>Deterministic DNF5 versionlock fixture</title>
    <issued date="2026-07-27 00:00:00"/>
    <updated date="2026-07-27 00:00:00"/>
    <severity>Important</severity>
    <summary>Fixture security update</summary>
    <description>Fixture security update</description>
    <solution>Update the fixture package.</solution>
    <references/>
    <pkglist>
      <collection short="sun-versionlock">
        <name>SUN DNF5 fixture</name>
        <package name="sun-versionlock-fixture" epoch="0" version="2.0" release="1" arch="noarch" filename="$new_name">
          <sum type="sha256">$fixture_sha</sum>
        </package>
      </collection>
    </pkglist>
  </update>
</updates>
EOF
modifyrepo_c --mdtype=updateinfo "$work/updateinfo.xml" "$repo/repodata"
cat >"$reposdir/sun-versionlock.repo" <<EOF
[sun-versionlock]
name=SUN deterministic versionlock fixture
baseurl=file://$repo
enabled=1
gpgcheck=0
repo_gpgcheck=0
metadata_expire=0
EOF

dnf -q --setopt="reposdir=$reposdir" makecache
set +e
dnf -q --setopt="reposdir=$reposdir" check-upgrade --security >"$work/before-lock.out" 2>&1
before_lock_rc=$?
set -e
[[ "$before_lock_rc" -eq 100 ]]
grep -Eq '^sun-versionlock-fixture\.noarch[[:space:]]+2\.0-1([[:space:]]|$)' "$work/before-lock.out"

dnf -q --setopt="reposdir=$reposdir" versionlock add sun-versionlock-fixture
versionlock=/etc/dnf/versionlock.toml
[[ -f "$versionlock" ]]
versionlock_before="$(sha256sum "$versionlock"; stat -c '%s|%y|%a|%u|%g' "$versionlock")"

set +e
dnf -q --setopt="reposdir=$reposdir" check-upgrade --security >"$work/locked.out" 2>&1
locked_rc=$?
dnf -q --no-plugins --setopt="reposdir=$reposdir" check-upgrade --security >"$work/no-plugins.out" 2>&1
no_plugins_rc=$?
dnf -q '--setopt=disable_excludes=*' --setopt="reposdir=$reposdir" check-upgrade --security >"$work/unrestricted.out" 2>&1
unrestricted_rc=$?
set -e
[[ "$locked_rc" -eq 0 && "$no_plugins_rc" -eq 0 && "$unrestricted_rc" -eq 100 ]]
if grep -Fq 'sun-versionlock-fixture.noarch' "$work/locked.out"; then
  echo 'versionlocked update unexpectedly remained visible with plugins enabled' >&2
  exit 1
fi
if grep -Fq 'sun-versionlock-fixture.noarch' "$work/no-plugins.out"; then
  echo 'versionlocked update unexpectedly remained visible with plugins disabled' >&2
  exit 1
fi
grep -Eq '^sun-versionlock-fixture\.noarch[[:space:]]+2\.0-1([[:space:]]|$)' "$work/unrestricted.out"

versionlock_after="$(sha256sum "$versionlock"; stat -c '%s|%y|%a|%u|%g' "$versionlock")"
[[ "$versionlock_after" == "$versionlock_before" ]]
echo "Fedora $VERSION_ID DNF5 versionlock bypass gate passed"
