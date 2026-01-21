#!/usr/bin/env python3
"""
Package ChatFilter as a portable distribution.

This script creates portable ZIP/tar.gz archives for different platforms.
The portable version includes the executable, dependencies, and documentation
in a single archive that requires no installation.

Usage:
    python scripts/package_portable.py [options]

Options:
    --platform {windows,macos,linux}  Target platform (default: detect)
    --version VERSION                  Version string (default: auto-detect)
    --build                           Run build before packaging
    --output DIR                      Output directory (default: packages/)
    --help                            Show this help message

Examples:
    # Package current platform with auto-detected version
    python scripts/package_portable.py

    # Build and package Windows version
    python scripts/package_portable.py --platform windows --build

    # Package specific version
    python scripts/package_portable.py --version 1.2.3
"""

import argparse
import hashlib
import platform
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Literal


def get_version() -> str:
    """Auto-detect version from pyproject.toml."""
    pyproject_path = Path("pyproject.toml")
    if not pyproject_path.exists():
        print("Warning: pyproject.toml not found, using default version 0.1.0")
        return "0.1.0"

    try:
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)
        version = str(data.get("project", {}).get("version", "0.1.0"))
        print(f"Auto-detected version: {version}")
        return version
    except Exception as e:
        print(f"Warning: Failed to read version from pyproject.toml: {e}")
        return "0.1.0"


def detect_platform() -> Literal["windows", "macos", "linux"]:
    """Detect the current platform."""
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    elif system == "linux":
        return "linux"
    elif system == "windows":
        return "windows"
    else:
        raise RuntimeError(f"Unsupported platform: {system}")


def run_build(target_platform: str) -> None:
    """Run the build script for the target platform."""
    print("Running build script...")
    if target_platform == "windows":
        result = subprocess.run(["build.bat"], shell=False)  # noqa: S603
    else:
        result = subprocess.run(["./build.sh"], shell=False)  # noqa: S603

    if result.returncode != 0:
        raise RuntimeError("Build failed")
    print("Build completed successfully\n")


def verify_build_exists(target_platform: str) -> Path:
    """Verify that the build output exists and return its path."""
    if target_platform == "windows":
        dist_dir = Path("dist/ChatFilter")
        exe_path = dist_dir / "ChatFilter.exe"
        if not exe_path.exists():
            raise FileNotFoundError(
                f"Build not found: {exe_path}\nRun build.bat first or use --build flag"
            )
    elif target_platform == "macos":
        dist_dir = Path("dist/ChatFilter.app")
        if not dist_dir.exists():
            raise FileNotFoundError(
                f"Build not found: {dist_dir}\nRun ./build.sh first or use --build flag"
            )
    else:  # linux
        dist_dir = Path("dist/ChatFilter")
        exe_path = dist_dir / "ChatFilter"
        if not exe_path.exists():
            raise FileNotFoundError(
                f"Build not found: {exe_path}\nRun ./build.sh first or use --build flag"
            )

    return dist_dir


def prepare_package_contents(dist_dir: Path, target_platform: str) -> None:
    """Copy documentation and configuration files to the distribution directory."""
    print("Preparing package contents...")

    # Copy README.portable.txt as README.txt
    readme_src = Path("README.portable.txt")
    if readme_src.exists():
        readme_dst = dist_dir / "README.txt"
        shutil.copy2(readme_src, readme_dst)
        print(f"  ✓ Copied README.portable.txt -> {readme_dst.name}")
    else:
        print("  ⚠ Warning: README.portable.txt not found")

    # Copy .env.example
    env_example_src = Path(".env.example")
    if env_example_src.exists():
        env_example_dst = dist_dir / ".env.example"
        shutil.copy2(env_example_src, env_example_dst)
        print("  ✓ Copied .env.example")
    else:
        print("  ⚠ Warning: .env.example not found")

    print()


def create_archive(
    dist_dir: Path,
    output_dir: Path,
    target_platform: str,
    version: str,
) -> tuple[Path, Path]:
    """Create compressed archive and checksum file."""
    # Determine archive format and extension
    if target_platform == "windows":
        archive_format = "zip"
        archive_ext = "zip"
    else:
        archive_format = "gztar"
        archive_ext = "tar.gz"

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Set archive filename
    platform_name = target_platform.capitalize()
    archive_name = f"ChatFilter-{platform_name}-Portable-v{version}"
    archive_path = output_dir / f"{archive_name}.{archive_ext}"

    print(f"Creating {archive_ext.upper()} archive...")
    print(f"  Target: {archive_path}")

    # Remove old archive if exists
    if archive_path.exists():
        archive_path.unlink()

    # Create archive
    # For ZIP: use shutil.make_archive
    # For tar.gz: use shutil.make_archive with gztar format
    base_name = str(output_dir / archive_name)
    root_dir = dist_dir.parent
    base_dir = dist_dir.name

    shutil.make_archive(
        base_name=base_name,
        format=archive_format,
        root_dir=root_dir,
        base_dir=base_dir,
    )

    # Verify archive was created
    if not archive_path.exists():
        raise RuntimeError(f"Failed to create archive: {archive_path}")

    # Get archive size
    size_mb = archive_path.stat().st_size / (1024 * 1024)
    print(f"  ✓ Archive created: {size_mb:.1f} MB\n")

    # Generate SHA256 checksum
    print("Generating SHA256 checksum...")
    checksum_path = archive_path.with_suffix(archive_path.suffix + ".sha256")

    hash_sha256 = hashlib.sha256()
    with open(archive_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)

    checksum = hash_sha256.hexdigest()
    with open(checksum_path, "w") as f:
        f.write(f"{checksum}  {archive_path.name}\n")

    print(f"  ✓ Checksum: {checksum}")
    print(f"  ✓ Saved to: {checksum_path.name}\n")

    return archive_path, checksum_path


def cleanup_package_contents(dist_dir: Path) -> None:
    """Remove temporary files added during packaging."""
    print("Cleaning up temporary files...")

    files_to_remove = [
        dist_dir / "README.txt",
        dist_dir / ".env.example",
    ]

    for file_path in files_to_remove:
        if file_path.exists():
            file_path.unlink()
            print(f"  ✓ Removed {file_path.name}")

    print()


def print_success_summary(
    archive_path: Path,
    checksum_path: Path,
    version: str,
    target_platform: str,
) -> None:
    """Print success message with distribution checklist."""
    size_mb = archive_path.stat().st_size / (1024 * 1024)

    print("=" * 60)
    print("Portable package created successfully!")
    print("=" * 60)
    print()
    print(f"Platform: {target_platform.capitalize()}")
    print(f"Version: {version}")
    print(f"Package: {archive_path}")
    print(f"Size: {size_mb:.1f} MB")
    print(f"Checksum: {checksum_path}")
    print()
    print("Contents:")
    if target_platform == "windows":
        print("  - ChatFilter.exe         (Main executable)")
    elif target_platform == "macos":
        print("  - ChatFilter.app         (macOS application bundle)")
    else:
        print("  - ChatFilter             (Linux executable)")
    print("  - _internal/             (Dependencies)")
    print("  - README.txt             (Usage instructions)")
    print("  - .env.example           (Configuration template)")
    print()
    print("DISTRIBUTION CHECKLIST:")
    print("  [ ] Test archive extraction")
    print("  [ ] Test executable runs without Python")
    print("  [ ] Verify README.txt is readable")
    print("  [ ] Check .env.example is present")
    print("  [ ] Verify SHA256 checksum matches")
    if target_platform == "windows":
        print("  [ ] Test on clean Windows 10/11 system")
    elif target_platform == "macos":
        print("  [ ] Test on clean macOS system")
    else:
        print("  [ ] Test on clean Linux system")
    print("  [ ] Upload to GitHub Releases")
    print("  [ ] Update download links in documentation")
    print()


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Package ChatFilter as a portable distribution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--platform",
        choices=["windows", "macos", "linux"],
        help="Target platform (default: auto-detect)",
    )
    parser.add_argument(
        "--version",
        help="Version string (default: auto-detect from pyproject.toml)",
    )
    parser.add_argument(
        "--build",
        action="store_true",
        help="Run build before packaging",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("packages"),
        help="Output directory (default: packages/)",
    )

    args = parser.parse_args()

    try:
        # Determine platform
        target_platform = args.platform or detect_platform()
        print(f"Target platform: {target_platform}")
        print()

        # Determine version
        version = args.version or get_version()
        print()

        # Build if requested
        if args.build:
            run_build(target_platform)

        # Verify build exists
        dist_dir = verify_build_exists(target_platform)
        print(f"Build found: {dist_dir}")
        print()

        # Prepare package contents
        prepare_package_contents(dist_dir, target_platform)

        # Create archive
        archive_path, checksum_path = create_archive(
            dist_dir=dist_dir,
            output_dir=args.output,
            target_platform=target_platform,
            version=version,
        )

        # Cleanup temporary files
        cleanup_package_contents(dist_dir)

        # Print success summary
        print_success_summary(
            archive_path=archive_path,
            checksum_path=checksum_path,
            version=version,
            target_platform=target_platform,
        )

        return 0

    except Exception as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
