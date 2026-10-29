"""Validate/stage a complete panel archive offline; never change a live tree."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from panel_backup import BackupError, read_archive, stage_restore
from peer_recovery import RecoveryError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True)
    parser.add_argument('--stage-to', help='NEW private directory, never the existing state directory')
    parser.add_argument('--confirm')
    args = parser.parse_args()
    try:
        if args.stage_to:
            result = stage_restore(args.archive, args.stage_to, args.confirm)
        else:
            manifest, files, checksum = read_archive(args.archive)
            result = {'status': 'verified', 'files': len(files), 'panel_version': manifest.get('panel_version'),
                      'sha256': checksum, 'counters_verified_final': False}
        print(json.dumps(result))
    except (BackupError, RecoveryError, OSError, ValueError):
        print('Backup not verified/staged. Preserve existing state and inspect private storage. No live restore was performed.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
