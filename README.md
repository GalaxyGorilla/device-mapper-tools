# device-mapper-tools

Small utilities related to Linux device-mapper.

## dm-integrity offline formatter (unprivileged)

`tools/dm-integrity/dm_integrity_offline_format.py` formats a **dm-integrity meta_device** image file offline, without needing `CAP_SYS_ADMIN` (no dmsetup/loop/devmapper ioctls). This is useful for CI pipelines that can create artifacts unprivileged, and only activate dm-integrity in a privileged stage.

### Quick start

```bash
truncate -s 64M data.img
python3 tools/dm-integrity/dm_integrity_offline_format.py \
  --data-image data.img \
  --meta-image integrity.meta.img
```

### Privileged smoke test

```bash
./tools/dm-integrity/dm_integrity_selftest.sh 64
```

