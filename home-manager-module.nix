{ config, lib, pkgs, ... }:
let
  cfg = config.services.zkapi-clientd;
  serviceUtils = import ./service-utils.nix { inherit lib; };
in {
  options.services.zkapi-clientd = {
    enable = lib.mkEnableOption "Open Anonymity's Linux user service";
    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix { };
      description = "The daemon and its matching companion/proof package.";
    };
    configDir = lib.mkOption {
      type = lib.types.str;
      default = "${config.xdg.configHome}/zkapi-clientd";
      description = "Runtime private directory initialized separately with zkapi-clientd config; never put credentials or wallet contents in Nix.";
    };
    startAtLogin = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Start the user service at login after its configuration exists.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      { assertion = pkgs.stdenv.hostPlatform.isLinux; message = "services.zkapi-clientd requires Linux systemd; on macOS use the package with zkapi-clientd serve."; }
      { assertion = lib.hasPrefix "/" cfg.configDir && serviceUtils.validPrivateDir cfg.configDir;
        message = "services.zkapi-clientd.configDir must be an absolute runtime directory outside the Nix store, without parent-directory components."; }
    ];
    home.packages = [ cfg.package ];
    systemd.user.services.zkapi-clientd = {
      Unit = {
        Description = "Open Anonymity local inference API";
        Documentation = [ "https://github.com/ethereum/zkapi" ];
        ConditionPathExists = "${cfg.configDir}/config.json";
        StartLimitIntervalSec = 60;
        StartLimitBurst = 5;
      };
      Service = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/zkapi-clientd serve";
        Environment = [ (serviceUtils.environmentValue "ZKAPI_CLIENTD_CONFIG_DIR=${cfg.configDir}") ];
        Restart = "on-failure";
        RestartSec = 5;
        TimeoutStopSec = 30;
        UMask = "0077";
        NoNewPrivileges = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
      };
      Install.WantedBy = lib.optionals cfg.startAtLogin [ "default.target" ];
    };
  };
}
