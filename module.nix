flake:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    concatMap
    mkEnableOption
    mkMerge
    mkOption
    mkIf
    mkForce
    mkOverride
    optionalAttrs
    types
    ;
  inherit (lib.kernel)
    freeform
    option
    yes
    no
    ;

  cfg = config.bunker.kernel;

  # Map user-facing major.minor → latest stable point release
  stableRelease = {
    "6.18" = "6.18.10";
    "6.19" = "6.19";
  };

  resolvedVersion = stableRelease.${cfg.version}
    or (throw "bunker: unsupported kernel version ${cfg.version}");

  # "6.18.10" → "6.18", "6.19" → "6.19"
  majorMinor = cfg.version;

  # "6.18" → "6.18.10", "6.19" → "6.19.0"
  fullVersion =
    let
      parts = lib.splitString "." resolvedVersion;
    in
    if builtins.length parts >= 3 then resolvedVersion else "${resolvedVersion}.0";

  # Patch group → 4-digit prefix strings
  patchGroups = {
    base = [ "0015" ];
    interactive = [
      "0003"
      "0011"
      "0012"
      "0014"
      "0016"
      "0017"
      "0018"
      "0019"
      "0020"
      "0021"
      "0022"
      "0023"
      "0024"
      "0025"
      "0028"
      "0029"
      "0030"
      "0031"
      "0032"
      "0033"
      "0039"
      "0040"
      "0043"
      "0044"
      "0045"
      "0051"
      "0053"
      "0054"
      "0055"
      "0171"
      "0172"
      "0173"
      "0174"
      "0175"
      "0176"
      "0177"
      "0178"
      "0185"
      "0186"
      "0187"
      "0188"
      "0189"
      "0190"
      "0194"
      "0195"
    ];
    hardened = [
      "0006"
      "0007"
      "0056"
    ]
    ++ (lib.genList (
      i:
      let
        n = i + 60;
      in
      lib.fixedWidthString 4 "0" (toString n)
    ) 107)
    # 0060..0166
    ++ [
      "0182"
      "0183"
      "0184"
    ];
    networking = [
      "0027"
      "0052"
      "0167"
      "0168"
      "0169"
      "0170"
      "0191"
      "0192"
      "0193"
      "0196"
      "0197"
      "0198"
      "0199"
      "0200"
      "0201"
      "0202"
      "0203"
    ];
    drivers = [
      "0001"
      "0002"
      "0004"
      "0005"
      "0008"
      "0009"
      "0010"
      "0013"
      "0026"
      "0034"
      "0036"
      "0037"
      "0038"
      "0042"
      "0057"
      "0179"
      "0180"
    ];
    extras = [
      "0035"
      "0041"
      "0046"
      "0047"
      "0048"
      "0049"
      "0050"
      "0058"
      "0059"
    ];
  };

  # Per-version extra patches (upstreamed or version-specific).
  # 6.19-only patches (0186-0190 TEO, 0198 fq-tweak) are in shared groups
  # and naturally skipped in 6.18 where the files don't exist.
  versionExtra = {
    "6.18" = {
      drivers = [ "0204" "0206" ];
      extras = [ "0205" ];
    };
  };

  extra = versionExtra.${majorMinor} or { };

  enabledGroups = [
    "base"
  ]
  ++ lib.optional cfg.interactive "interactive"
  ++ lib.optional cfg.hardened "hardened"
  ++ lib.optional cfg.networking "networking"
  ++ lib.optional cfg.drivers "drivers"
  ++ lib.optional cfg.extras "extras";

  enabledNumbers = concatMap (g: patchGroups.${g} ++ (extra.${g} or [ ])) enabledGroups;
  enabledSet = lib.genAttrs enabledNumbers (_: true);

  # All patch files from the patches directory, sorted numerically
  patchDir = "${flake}/patches/${majorMinor}";
  allPatchFiles =
    builtins.filter (n: lib.hasSuffix ".patch" n) (builtins.attrNames (builtins.readDir patchDir))
    |> builtins.sort builtins.lessThan;

  # Filter patches by prefix membership, preserving numeric order
  selectedPatches = builtins.filter (name: enabledSet ? ${builtins.substring 0 4 name}) allPatchFiles;

  kernelPatches = map (name: {
    inherit name;
    patch = "${patchDir}/${name}";
  }) selectedPatches;

  # Full LLVM stdenv with clang + lld + llvm-ar/nm (required for LTO_CLANG / CFI)
  llvmStdenv = pkgs.overrideCC pkgs.llvmPackages.stdenv (
    pkgs.llvmPackages.clang.override {
      bintools = pkgs.llvmPackages.bintools;
    }
  );

  sourceHash =
    {
      "6.18.10" = "sha256-1tN3FhdBraL6so7taRQyd2NKKuteOIPlDAMViO3kjt4=";
      "6.19" = "sha256-MDB5qCULjzgfgrA/kEY9EqyY1PaxSbdh6nWvEyNSE1c=";
    }
    .${resolvedVersion};

  kernelSrc = pkgs.fetchurl {
    url = "https://cdn.kernel.org/pub/linux/kernel/v${
      builtins.substring 0 1 cfg.version
    }.x/linux-${resolvedVersion}.tar.xz";
    hash = sourceHash;
  };

  # Per-group structured kconfig.
  # Uses optionalAttrs (not mkIf) because these are merged with // into buildLinux,
  # which is outside the module system's merging.
  baseConfig = {
    BUNKER = yes;
    LOCALVERSION = freeform "-bunker";
    MODULE_COMPRESS_ZSTD = mkForce yes;
    MODULE_COMPRESS_XZ = mkForce no;
  };

  interactiveConfig = optionalAttrs cfg.interactive {
    PREEMPT = mkOverride 90 yes;
    PREEMPT_VOLUNTARY = mkOverride 90 no;
    HZ = freeform "1000";
    HZ_1000 = yes;
    IOSCHED_BFQ = mkOverride 90 yes;
    MQ_IOSCHED_ADIOS = yes;
    TRANSPARENT_HUGEPAGE_ALWAYS = mkForce yes;
    TRANSPARENT_HUGEPAGE_MADVISE = mkForce no;
    MQ_IOSCHED_KYBER = mkForce no;
    BLK_WBT = mkForce no;
    BLK_WBT_MQ = mkForce (option no);
    FUTEX = yes;
    FUTEX_PI = yes;
    NTSYNC = yes;
    TREE_RCU = yes;
    PREEMPT_RCU = yes;
    RCU_EXPERT = yes;
    TREE_SRCU = yes;
    TASKS_RCU_GENERIC = yes;
    TASKS_RCU = yes;
    TASKS_RUDE_RCU = yes;
    TASKS_TRACE_RCU = yes;
    RCU_STALL_COMMON = yes;
    RCU_NEED_SEGCBLIST = yes;
    RCU_FANOUT = freeform "64";
    RCU_FANOUT_LEAF = freeform "16";
    RCU_BOOST = yes;
    RCU_BOOST_DELAY = option (freeform "500");
    RCU_NOCB_CPU = yes;
    RCU_LAZY = yes;
    RCU_DOUBLE_CHECK_CB_TIME = yes;
    X86_AMD_PSTATE = yes;
    X86_AMD_PSTATE_DEFAULT_MODE = freeform "3";
  };

  hardenedConfig = optionalAttrs cfg.hardened {
    STRICT_DEVMEM = mkForce (option no);
    IO_STRICT_DEVMEM = mkForce (option no);
    CFI = yes;
    CFI_PERMISSIVE = no;
    ZERO_CALL_USED_REGS = yes;
    SECURITY_SAFESETID = yes;

    # --- Dead network protocols ---
    ATALK = option no; # Appletalk
    ATM = option no; # Async Transfer Mode
    AX25 = option no; # Amateur radio X.25
    CAN = option no; # Controller Area Network
    DECNET = option no; # DECnet
    HAMRADIO = option no; # Amateur radio umbrella (ax25/netrom/rose)
    IEEE802154 = option no; # Wireless sensor networks
    IP_DCCP = option no; # Datagram Congestion Control
    IP_SCTP = option no; # Stream Control Transmission
    IPX = option no; # Internetwork Packet Exchange
    NETROM = option no; # Amateur radio NetRom
    N_HDLC = option no; # HDLC line discipline
    ROSE = option no; # Amateur radio ROSE
    RDS = option no; # Reliable Datagram Sockets
    TIPC = option no; # Transparent IPC
    X25 = option no; # X.25 packet switching
    AF_RXRPC = option no; # RxRPC sessions (only for AFS)
    AF_KCM = option no; # Kernel Connection Multiplexor
    PHONET = option no; # Nokia Phonet
    CAIF = option no; # ST-Ericsson modem IPC
    "6LOWPAN" = option no; # IPv6 over low-power networks
    NFC = option no; # Near Field Communication
    WIMAX = option no; # WiMAX (dead standard)
    MCTP = option no; # Management Component Transport
    QRTR = option no; # Qualcomm IPC Router
    HSR = option no; # High-availability Seamless Redundancy
    MPLS = option no; # MPLS label switching
    BATMAN_ADV = option no; # B.A.T.M.A.N. mesh
    NET_DSA = option no; # Distributed Switch Architecture

    # --- Server/cloud networking ---
    OPENVSWITCH = option no; # Virtual switch (SDN)
    VXLAN = option no; # Cloud overlay
    GENEVE = option no; # Cloud overlay
    NET_TEAM = option no; # Network teaming
    BONDING = option no; # NIC bonding
    MACSEC = option no; # 802.1AE MAC encryption
    NET_SWITCHDEV = option no; # Switch offload

    # --- Dead/unused filesystems ---
    ADFS_FS = option no;
    AFFS_FS = option no;
    AFS_FS = option no; # Andrew File System
    BEFS_FS = option no;
    BFS_FS = option no;
    CEPH_FS = option no;
    CIFS = mkForce (option no); # NixOS might enable
    CRAMFS = option no;
    EFS_FS = option no;
    EROFS_FS = option no;
    F2FS_FS = option no;
    GFS2_FS = option no;
    HFS_FS = option no;
    HFSPLUS_FS = option no;
    HPFS_FS = option no;
    JFFS2_FS = option no;
    JFS_FS = option no;
    MINIX_FS = option no;
    NFS_FS = mkForce (option no); # NixOS enables by default
    NILFS2_FS = option no;
    OCFS2_FS = option no;
    OMFS_FS = option no;
    ORANGEFS_FS = option no;
    QNX4FS_FS = option no;
    QNX6FS_FS = option no;
    REISERFS_FS = option no;
    SMB_SERVER = option no; # ksmbd
    SQUASHFS = mkForce (option no); # NixOS might enable
    SYSV_FS = option no;
    UDF_FS = option no;
    VXFS_FS = option no; # freevxfs
    ZONEFS_FS = option no;
    "9P_FS" = option no; # Plan 9

    # --- Dead subsystems ---
    FIREWIRE = option no; # IEEE 1394
    INFINIBAND = option no; # RDMA/InfiniBand
    ISDN = option no; # ISDN telephony
    PCMCIA = option no; # CardBus
    PARPORT = option no; # Parallel port
    GAMEPORT = option no; # Legacy gameport
    COMEDI = option no; # Data acquisition
    GREYBUS = option no; # Project Ara
    STAGING = option no; # Experimental drivers

    # --- Server block/storage ---
    BLK_DEV_NBD = option no; # Network block device
    BLK_DEV_RBD = option no; # Ceph/RADOS block
    TARGET_CORE = option no; # SCSI target
    ISCSI_TCP = option no; # iSCSI initiator
    NVME_TARGET = option no; # NVMe-oF target

    # --- Legacy/deprecated ---
    USELIB = option no; # a.out uselib() syscall
    SYSFS_SYSCALL = option no; # old sysfs() syscall
    PCSPKR_PLATFORM = option no; # PC speaker
    KEXEC = option no; # kexec (disabled at runtime anyway)

    # --- VM guest (not applicable to bare-metal desktop) ---
    DRM_VIRTIO_GPU = option no; # Virtio GPU
    VIDEO_VIVID = option no; # Virtual video test driver
  };

  networkingConfig = optionalAttrs cfg.networking {
    TCP_CONG_BBR = yes;
    DEFAULT_BBR = yes;
    NET_SCH_DEFAULT = yes;
    DEFAULT_FQ_CODEL = yes;
  };

  rustLtoConfig = optionalAttrs (cfg.rust && cfg.lto != "none") {
    DEBUG_INFO_BTF = mkForce no;
    NOVA_CORE = mkForce (option no);
    NET_SCH_BPF = mkForce (option no);
    SCHED_CLASS_EXT = mkForce (option no);
    MODULE_ALLOW_BTF_MISMATCH = mkForce (option no);
    MODVERSIONS = mkForce no;
  };

  ltoConfig =
    {
      "full" = {
        LTO_CLANG_FULL = yes;
        LTO_CLANG_THIN = mkForce no;
      };
      "thin" = {
        LTO_CLANG_THIN = yes;
        LTO_CLANG_FULL = mkForce no;
      };
      "none" = { };
    }
    .${cfg.lto};

  cpuArchConfig = optionalAttrs (cfg.cpuArch != null) {
    ${cfg.cpuArch} = yes;
  };

  bunkernel = pkgs.linuxKernel.buildLinux {
    pname = "linux-bunker";
    stdenv = llvmStdenv;
    src = kernelSrc;
    version = fullVersion;
    modDirVersion = "${fullVersion}-bunker";
    inherit kernelPatches;

    structuredExtraConfig =
      baseConfig
      // interactiveConfig
      // hardenedConfig
      // networkingConfig
      // rustLtoConfig
      // ltoConfig
      // cpuArchConfig;

    extraMeta = {
      branch = majorMinor;
      description = "Bunker kernel";
    };
  };

  kernelPackage = pkgs.linuxKernel.packagesFor (
    bunkernel.overrideAttrs (old: {
      # The Clang+LTO+Rust kernel binary embeds build tool store paths
      # (CC, LD, RUSTC, etc.) that Nix's reference scanner picks up as
      # runtime dependencies.  The kernel image is loaded by the bootloader
      # and has zero legitimate runtime store-path dependencies, so we can
      # safely discard all detected references from $out.
      # Requires __structuredAttrs = true (already set by nixpkgs' buildLinux).
      unsafeDiscardReferences = (old.unsafeDiscardReferences or { }) // {
        out = true;
      };

      postInstall =
        builtins.replaceStrings
          [ "# Keep whole scripts dir" ]
          [
            ''
              # Keep rust Makefile and source files for rust-analyzer support
                        [ -f rust/Makefile ] && chmod u-w rust/Makefile
                        find rust -type f -name '*.rs' -print0 | xargs -0 -r chmod u-w

                        # Keep whole scripts dir''
          ]
          (old.postInstall or "");
    })
  );
in
{
  options.bunker.kernel = {
    enable = mkEnableOption "Bunker kernel";

    version = mkOption {
      type = types.enum [
        "6.18"
        "6.19"
      ];
      default = "6.19";
      description = "Linux kernel major.minor version. Automatically resolves to the latest stable point release.";
    };

    interactive = mkOption {
      type = types.bool;
      default = true;
      description = "Enable interactive/desktop performance patches (preempt, BFQ, RCU tuning, etc.).";
    };

    hardened = mkOption {
      type = types.bool;
      default = true;
      description = "Enable linux-hardened security patches (CFI, RANDSTRUCT, slab hardening, etc.).";
    };

    networking = mkOption {
      type = types.bool;
      default = true;
      description = "Enable networking patches (BBRv3, FQ-Codel).";
    };

    drivers = mkOption {
      type = types.bool;
      default = true;
      description = "Enable driver patches (ACS override, AMDGPU, HDMI, Bluetooth quirks, etc.).";
    };

    extras = mkOption {
      type = types.bool;
      default = true;
      description = "Enable extra patches (sched_ext, v4l2loopback, Clang Polly, micro-arch targets, etc.).";
    };

    cpuArch = mkOption {
      type = types.nullOr (types.enum [
        "GENERIC_CPU"
        "X86_NATIVE_CPU"
        # AMD
        "MK8"
        "MK8SSE3"
        "MK10"
        "MBARCELONA"
        "MBOBCAT"
        "MJAGUAR"
        "MBULLDOZER"
        "MPILEDRIVER"
        "MSTEAMROLLER"
        "MEXCAVATOR"
        "MZEN"
        "MZEN2"
        "MZEN3"
        "MZEN4"
        "MZEN5"
        # Intel
        "MPSC"
        "MCORE2"
        "MNEHALEM"
        "MWESTMERE"
        "MSILVERMONT"
        "MGOLDMONT"
        "MGOLDMONTPLUS"
        "MSANDYBRIDGE"
        "MIVYBRIDGE"
        "MHASWELL"
        "MBROADWELL"
        "MSKYLAKE"
        "MSKYLAKEX"
        "MCANNONLAKE"
        "MICELAKE_CLIENT"
        "MICELAKE_SERVER"
        "MCOOPERLAKE"
        "MCASCADELAKE"
        "MTIGERLAKE"
        "MSAPPHIRERAPIDS"
        "MROCKETLAKE"
        "MALDERLAKE"
        "MRAPTORLAKE"
        "MMETEORLAKE"
        "MEMERALDRAPIDS"
      ]);
      default = null;
      description = "CPU micro-architecture Kconfig target. Requires extras group.";
      example = "MZEN5";
    };

    lto = mkOption {
      type = types.enum [
        "full"
        "thin"
        "none"
      ];
      default = "full";
      description = "LTO mode for Clang.";
    };

    rust = mkOption {
      type = types.bool;
      default = true;
      description = "Enable Rust support in the kernel.";
    };
  };

  config = mkIf cfg.enable (mkMerge [
    {
      assertions = [
        {
          assertion = cfg.cpuArch == null || cfg.extras;
          message = "bunker.kernel.cpuArch requires extras group (patch 0046 adds micro-arch targets).";
        }
      ];

      boot.kernelPackages = kernelPackage;
    }

    (mkIf cfg.hardened {
      boot.kernel.sysctl = {
        # Disable Magic SysRq key — potential security concern.
        "kernel.sysrq" = 0;
        # Hide kptrs even for processes with CAP_SYSLOG.
        "kernel.kptr_restrict" = 2;
        # Disable bpf() JIT (eliminates spray attacks).
        "net.core.bpf_jit_enable" = false;
        # Disable ftrace debugging.
        "kernel.ftrace_enabled" = false;
        # Restrict dmesg to root (CONFIG_SECURITY_DMESG_RESTRICT equivalent).
        "kernel.dmesg_restrict" = 1;
        # Prevent unintentional fifo writes.
        "fs.protected_fifos" = 2;
        # Prevent unintended writes to already-created files.
        "fs.protected_regular" = 2;
        # Disable SUID binary dump.
        "fs.suid_dumpable" = 0;
        # Disallow profiling without CAP_SYS_ADMIN.
        "kernel.perf_event_paranoid" = 3;
        # Require CAP_BPF to use bpf.
        "kernel.unprivileged_bpf_disabled" = 1;

        # --- Network hardening ---
        # SYN flood protection.
        "net.ipv4.tcp_syncookies" = 1;
        # TIME-WAIT assassination protection (RFC 1337).
        "net.ipv4.tcp_rfc1337" = 1;
        # Reverse path filtering — drop spoofed-source packets.
        "net.ipv4.conf.all.rp_filter" = 1;
        "net.ipv4.conf.default.rp_filter" = 1;
        # Disable ICMP redirects — prevents MITM via fake route injection.
        "net.ipv4.conf.all.accept_redirects" = 0;
        "net.ipv4.conf.default.accept_redirects" = 0;
        "net.ipv6.conf.all.accept_redirects" = 0;
        "net.ipv6.conf.default.accept_redirects" = 0;
        "net.ipv4.conf.all.send_redirects" = 0;
        "net.ipv4.conf.default.send_redirects" = 0;
        # Disable source routing.
        "net.ipv4.conf.all.accept_source_route" = 0;
        "net.ipv6.conf.all.accept_source_route" = 0;
        # Log martian packets.
        "net.ipv4.conf.all.log_martians" = 1;
        "net.ipv4.conf.default.log_martians" = 1;
      };

      boot.kernelParams = [
        "module.sig_enforce=1"
        "lockdown=confidentiality"
        "page_alloc.shuffle=1"
        "sysrq_always_enabled=0"
        "kcore=off"
      ];
    })

    (mkIf cfg.interactive {
      boot.kernelParams = [
        "fbcon=nodefer"
      ];
    })
  ]);
}
