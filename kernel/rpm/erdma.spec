
%define name			erdma
%define driver_name		erdma
%define debug_package		%{nil}

Name:		%{name}
Version:	%{driver_version}
Release:	9%{?dist}
Summary:	%{name} kernel module

Group:		System/Kernel
License:	Dual BSD/GPL
URL:		https://need-to-fix.com
Source0:	%{name}-%{version}.tar

Requires:	dkms %kernel_module_package_buildreqs cmake
# RHEL 8.4 has a broken dependency between cmake and libarchive which
# causes libarchive to not be updated properly in the update case. Express the
# dependency so that our install does not break.
%if 0%{?rhel} >= 8
Requires: libarchive >= 3.3.3
%endif

%define install_path /usr/src/%{driver_name}-%{version}

%description
%{name} kernel module source and DKMS scripts to build the kernel module.

%prep
%setup -n %{name}-%{version} -q

%post
cd %{install_path}
dkms add -m %{driver_name} -v %{driver_version}
for kernel in $(/bin/ls /lib/modules); do
	if [ -e /lib/modules/$kernel/build/include ]; then
		dkms build -m %{driver_name} -v %{driver_version} -k $kernel
		dkms install --force -m %{driver_name} -v %{driver_version} -k $kernel
	fi
done

%preun

if (dkms status | grep erdma); then
dkms remove -m %{driver_name} -v %{driver_version} --all
fi

%build

%install
mkdir -p %{buildroot}%{install_path}
mkdir -p %{buildroot}%{install_path}/config
mkdir -p %{buildroot}%{install_path}/src
mkdir -p %{buildroot}%{install_path}/src/compat
install -D -m 644 conf/erdma.conf		%{buildroot}/etc/modules-load.d/erdma.conf
install -D -m 644 conf/erdma-modprobe.conf	%{buildroot}/etc/modprobe.d/erdma.conf
install -m 644 conf/dkms.conf			%{buildroot}%{install_path}
install -m 744 conf/configure-dkms.sh		%{buildroot}%{install_path}
install -m 644 CMakeLists.txt			%{buildroot}%{install_path}
install -m 644 README				%{buildroot}%{install_path}
install -m 644 RELEASENOTES.md			%{buildroot}%{install_path}
install -m 644 config/Makefile			%{buildroot}%{install_path}/config
install -m 644 config/main.c.in			%{buildroot}%{install_path}/config
install -m 744 config/compile_conftest.sh	%{buildroot}%{install_path}/config
install -m 644 config/erdma.cmake		%{buildroot}%{install_path}/config
install -m 744 config/runbg.sh			%{buildroot}%{install_path}/config
install -m 744 config/wait_for_pid.sh		%{buildroot}%{install_path}/config
cd src
install -m 644 erdma.h			%{buildroot}%{install_path}/src
install -m 644 erdma_cmdq.c		%{buildroot}%{install_path}/src
install -m 644 erdma_cm.c		%{buildroot}%{install_path}/src
install -m 644 erdma_cm.h		%{buildroot}%{install_path}/src
install -m 644 erdma_cq.c		%{buildroot}%{install_path}/src
install -m 644 erdma_eq.c		%{buildroot}%{install_path}/src
install -m 644 erdma_hw.h		%{buildroot}%{install_path}/src
install -m 644 erdma_ioctl.h		%{buildroot}%{install_path}/src
install -m 644 erdma_ioctl.c		%{buildroot}%{install_path}/src
install -m 644 erdma_main.c		%{buildroot}%{install_path}/src
install -m 644 erdma_qp.c		%{buildroot}%{install_path}/src
install -m 644 erdma_stats.c		%{buildroot}%{install_path}/src
install -m 644 erdma_stats.h		%{buildroot}%{install_path}/src
install -m 644 erdma_debugfs.c		%{buildroot}%{install_path}/src
install -m 644 erdma_cmd.c		%{buildroot}%{install_path}/src
install -m 644 erdma_verbs.c		%{buildroot}%{install_path}/src
install -m 644 erdma_verbs.h		%{buildroot}%{install_path}/src
install -m 644 erdma-abi.h		%{buildroot}%{install_path}/src
install -m 644 kcompat.h		%{buildroot}%{install_path}/src
install -m 644 CMakeLists.txt		%{buildroot}%{install_path}/src
install -m 644 Kbuild.in		%{buildroot}%{install_path}/src
install -m 644 ofa.mk			%{buildroot}%{install_path}/src

install -m 644 erdma_compat.c		%{buildroot}%{install_path}/src
install -m 644 erdma_compat.h		%{buildroot}%{install_path}/src
install -m 644 erdma_verbs.c		%{buildroot}%{install_path}/src
install -m 644 erdma_verbs.h		%{buildroot}%{install_path}/src
install -m 644 compat/rdma_user_sw.h	%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw.h		%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_av.c		%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_comp.c		%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_cq.c		%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_dev.c		%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_hdr.h		%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_hw_counters.h	%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_icrc.c		%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_loc.h		%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_mcast.c	%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_mr.c		%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_net.c		%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_net.h		%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_opcode.c	%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_opcode.h	%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_param.h	%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_pool.c		%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_pool.h		%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_qp.c		%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_queue.c	%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_queue.h	%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_recv.c		%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_req.c		%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_resp.c		%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_task.c		%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_task.h		%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_verbs.c	%{buildroot}%{install_path}/src/compat
install -m 644 compat/sw_verbs.h	%{buildroot}%{install_path}/src/compat


%files
%{install_path}
/etc/modules-load.d/erdma.conf
/etc/modprobe.d/erdma.conf

%changelog
* Wed Jun 7 2023 Cheng Xu <chengyou.xc@linux.alibaba-inc.com> - 1.0.2
- Bump to internal version 0.2.37
- Get details from RELEASENOTES.md if needed.

* Thu Mar 9 2023 Cheng Xu <chengyou.xc@linux.alibaba-inc.com> - 1.0.1
- Bump to internal version 0.2.36

* Fri Mar 8 2019 Robert Wespetal <wesper@amazon.com> - 1.0.0
- initial build for RHEL
