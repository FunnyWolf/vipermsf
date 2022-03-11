# -*- coding: binary -*-

module Msf
class Post
module Linux
module Kernel
  include ::Msf::Post::Common
  include Msf::Post::File
  #
  # Returns uname output
  #
  # @return [String]
  #
  def uname(opts='-a')
    cmd_exec("uname #{opts}").to_s.strip
  rescue
    raise "Failed to run uname #{opts}"
  end

  #
  # Returns the kernel release
  #
  # @return [String]
  #
  def kernel_release
    uname('-r')
  end

  #
  # Returns the kernel version
  #
  # @return [String]
  #
  def kernel_version
    uname('-v')
  end

  #
  # Returns the kernel name
  #
  # @return [String]
  #
  def kernel_name
    uname('-s')
  end

  #
  # Returns the kernel hardware
  #
  # @return [String]
  #
  def kernel_hardware
    uname('-m')
  end

  #
  # Returns the kernel hardware architecture
  # Based on values from https://en.wikipedia.org/wiki/Uname
  #
  # @return [String]
  #
  def kernel_arch
    arch = kernel_hardware
    return ARCH_X64 if arch == 'x86_64' || arch == 'amd64'
    return ARCH_AARCH64 if arch == 'aarch64' || arch == 'arm64'
    return ARCH_ARMLE if arch.start_with?'arm'
    return ARCH_X86 if arch.end_with?'86'
    arch
  end

  #
  # Returns the kernel boot config
  #
  # @return [Array]
  #
  def kernel_config
   return unless cmd_exec('test -r /boot/config-`uname -r` && echo true').include? 'true'
    output = cmd_exec("cat /boot/config-`uname -r`").to_s.strip
    return if output.empty?
    config = output.split("\n").map(&:strip).reject(&:empty?).reject {|i| i.start_with? '#'}
    config
  rescue
    raise 'Could not retrieve kernel config'
  end

  #
  # Returns the kernel modules
  #
  # @return [Array]
  #
  def kernel_modules
    read_file('/proc/modules').to_s.scan(/^[^ ]+/)
  rescue
    raise 'Could not determine kernel modules'
  end

  #
  # Returns a list of CPU flags
  #
  # @return [Array]
  #
  def cpu_flags
    cpuinfo = read_file('/proc/cpuinfo').to_s

    return unless cpuinfo.include? 'flags'

    cpuinfo.scan(/^flags\s*:(.*)$/).flatten.join(' ').split(/\s/).map(&:strip).reject(&:empty?).uniq
  rescue
    raise'Could not retrieve CPU flags'
  end

  #
  # Returns true if kernel and hardware supports Supervisor Mode Access Prevention (SMAP), false if not.
  #
  # @return [Boolean]
  #
  def smap_enabled?
    cpu_flags.include? 'smap'
  rescue
    raise 'Could not determine SMAP status'
  end

  #
  # Returns true if kernel and hardware supports Supervisor Mode Execution Protection (SMEP), false if not.
  #
  # @return [Boolean]
  #
  def smep_enabled?
    cpu_flags.include? 'smep'
  rescue
    raise 'Could not determine SMEP status'
  end

  #
  # Returns true if Kernel Address Isolation (KAISER) is enabled
  #
  # @return [Boolean]
  #
  def kaiser_enabled?
    cpu_flags.include? 'kaiser'
  rescue
    raise 'Could not determine KAISER status'
  end

  #
  # Returns true if Kernel Page-Table Isolation (KPTI) is enabled, false if not.
  #
  # @return [Boolean]
  #
  def kpti_enabled?
    cpu_flags.include? 'pti'
  rescue
    raise 'Could not determine KPTI status'
  end

  #
  # Returns true if user namespaces are enabled, false if not.
  #
  # @return [Boolean]
  #
  def userns_enabled?
    return false if read_file('/proc/sys/user/max_user_namespaces').to_s.strip.eql? '0'
    return false if read_file('/proc/sys/kernel/unprivileged_userns_clone').to_s.strip.eql? '0'
    true
  rescue
    raise 'Could not determine userns status'
  end

  #
  # Returns true if Address Space Layout Randomization (ASLR) is enabled
  #
  # @return [Boolean]
  #
  def aslr_enabled?
    aslr = read_file('/proc/sys/kernel/randomize_va_space').to_s.strip
    (aslr.eql?('1') || aslr.eql?('2'))
  rescue
    raise 'Could not determine ASLR status'
  end

  #
  # Returns true if Exec-Shield is enabled
  #
  # @return [Boolean]
  #
  def exec_shield_enabled?
    exec_shield = read_file('/proc/sys/kernel/exec-shield').to_s.strip
    (exec_shield.eql?('1') || exec_shield.eql?('2'))
  rescue
    raise 'Could not determine exec-shield status'
  end

  #
  # Returns true if unprivileged bpf is disabled
  #
  # @return [Boolean]
  #
  def unprivileged_bpf_disabled?
    unprivileged_bpf_disabled = read_file('/proc/sys/kernel/unprivileged_bpf_disabled').to_s.strip
    return (unprivileged_bpf_disabled == '1' || unprivileged_bpf_disabled == '2')
  rescue
    raise 'Could not determine kernel.unprivileged_bpf_disabled status'
  end

  #
  # Returns true if kernel pointer restriction is enabled
  #
  # @return [Boolean]
  #
  def kptr_restrict?
    read_file('/proc/sys/kernel/kptr_restrict').to_s.strip.eql? '1'
  rescue
    raise 'Could not determine kernel.kptr_restrict status'
  end

  #
  # Returns true if dmesg restriction is enabled
  #
  # @return [Boolean]
  #
  def dmesg_restrict?
    read_file('/proc/sys/kernel/dmesg_restrict').to_s.strip.eql? '1'
  rescue
    raise 'Could not determine kernel.dmesg_restrict status'
  end

  #
  # Returns mmap minimum address
  #
  # @return [Integer]
  #
  def mmap_min_addr
    mmap_min_addr = read_file('/proc/sys/vm/mmap_min_addr').to_s.strip
    return 0 unless mmap_min_addr =~ /\A\d+\z/
    mmap_min_addr
  rescue
    raise 'Could not determine system mmap_min_addr'
  end

  #
  # Returns true if Linux Kernel Runtime Guard (LKRG) kernel module is installed
  #
  def lkrg_installed?
    directory?('/proc/sys/lkrg')
  rescue
    raise 'Could not determine LKRG status'
  end

  #
  # Returns true if grsecurity is installed
  #
  def grsec_installed?
    cmd_exec('test -c /dev/grsec && echo true').to_s.strip.include? 'true'
  rescue
    raise 'Could not determine grsecurity status'
  end

  #
  # Returns true if PaX is installed
  #
  def pax_installed?
    read_file('/proc/self/status').to_s.include? 'PaX:'
  rescue
    raise 'Could not determine PaX status'
  end

  #
  # Returns true if SELinux is installed
  #
  # @return [Boolean]
  #
  def selinux_installed?
    cmd_exec('id').to_s.include? 'context='
  rescue
    raise 'Could not determine SELinux status'
  end

  #
  # Returns true if SELinux is in enforcing mode
  #
  # @return [Boolean]
  #
  def selinux_enforcing?
    return false unless selinux_installed?

    sestatus = cmd_exec('/usr/sbin/sestatus').to_s.strip
    raise unless sestatus.include?('SELinux')

    return true if sestatus =~ /Current mode:\s*enforcing/
    false
  rescue
    raise 'Could not determine SELinux status'
  end

  #
  # Returns true if Yama is installed
  #
  # @return [Boolean]
  #
  def yama_installed?
    ptrace_scope = read_file('/proc/sys/kernel/yama/ptrace_scope').to_s.strip
    return true if ptrace_scope =~ /\A\d\z/
    false
  rescue
    raise 'Could not determine Yama status'
  end

  #
  # Returns true if Yama is enabled
  #
  # @return [Boolean]
  #
  def yama_enabled?
    return false unless yama_installed?
    !read_file('/proc/sys/kernel/yama/ptrace_scope').to_s.strip.eql? '0'
  rescue
    raise 'Could not determine Yama status'
  end
end # Kernel
end # Linux
end # Post
end # Msf
