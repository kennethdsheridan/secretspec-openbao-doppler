{
  description = "SecretSpec with OpenBao and Doppler providers";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      mkSystemContext = system:
        let
          pkgs = import nixpkgs { inherit system; };
          inherit (pkgs) lib stdenv;
          providerCliPackages = [
            pkgs.doppler
            pkgs.sops
          ];
        in
        {
          inherit pkgs lib stdenv providerCliPackages;
        };
    in
    {
      packages = forAllSystems (system:
        let
          inherit (mkSystemContext system) pkgs lib stdenv providerCliPackages;

          # The default Linux package is portable: build it against musl and
          # omit providers that require dynamic desktop libraries. Darwin keeps
          # its normal dynamic build and complete provider feature set.
          secretspec = (if stdenv.hostPlatform.isLinux
          then pkgs.pkgsStatic.rustPlatform
          else pkgs.rustPlatform).buildRustPackage {
            pname = "secretspec";
            version = "0.20.0";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [ "--package" "secretspec" ]
              ++ lib.optionals stdenv.hostPlatform.isLinux [
              "--no-default-features"
              "--features"
              "cli,openbao"
            ];
            cargoTestFlags = [ "--package" "secretspec" ];

            nativeBuildInputs = [ pkgs.makeWrapper ];

            # Darwin's complete dynamic build includes the keyring provider.
            buildInputs = lib.optionals stdenv.hostPlatform.isDarwin [
              pkgs.apple-sdk_15
              pkgs.libiconv
            ];

            postFixup = ''
              wrapArgs=(
                --prefix PATH : "${lib.makeBinPath providerCliPackages}"
                --set-default SSL_CERT_FILE "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
              )
              for program in "$out"/bin/*; do
                wrapProgram "$program" "''${wrapArgs[@]}"
              done
            '';

            # The workspace suite mutates process-global CLI and environment
            # state, so it is not safe to run in Nix's parallel sandbox.
            doCheck = false;

            meta = with lib; {
              description = "Declarative secrets CLI (musl-static on Linux; dynamic on Darwin)";
              homepage = "https://github.com/cachix/secretspec";
              license = licenses.asl20;
              mainProgram = "secretspec";
              platforms = systems;
            };
          };

          secretspec-derive = pkgs.rustPlatform.buildRustPackage {
            pname = "secretspec-derive";
            version = "0.20.0";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [ "--package" "secretspec-derive" ];
            cargoTestFlags = [ "--package" "secretspec-derive" ];

            meta = with lib; {
              description = "Procedural macros for SecretSpec";
              homepage = "https://github.com/cachix/secretspec";
              license = licenses.asl20;
              platforms = systems;
            };
          };
        in
        {
          default = secretspec;
          inherit secretspec secretspec-derive;
        });

      devShells = forAllSystems (system:
        let
          inherit (mkSystemContext system) pkgs lib stdenv providerCliPackages;
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              cargo
              rust-analyzer
              rustc
            ] ++ providerCliPackages ++ lib.optionals stdenv.hostPlatform.isLinux [
              dbus
              libsecret
              pkg-config
            ] ++ lib.optionals stdenv.hostPlatform.isDarwin [
              apple-sdk_15
              libiconv
            ];

            SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
            LD_LIBRARY_PATH = pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux
              "${pkgs.libsecret}/lib:${pkgs.dbus}/lib";
          };
        });

      overlays.default = final: prev: {
        secretspec = self.packages.${final.system}.secretspec;
      };
    };
}
