import pytsk3, hashlib, magic, io, json, pandas as pd
from Registry import Registry

MAGIC = magic.Magic(mime=True)

def open_image(image_path):
    img = pytsk3.Img_Info(str(image_path))
    vol = pytsk3.Volume_Info(img)
    ntfs_parts = [p for p in vol if b"NTFS" in p.desc]
    main_part = max(ntfs_parts, key=lambda p: p.len)

    offset = main_part.start * 512
    return img, offset

def hash_file(entry, chunk_size=1024*1024):
    sha256, md5 = hashlib.sha256(), hashlib.md5()
    size = entry.info.meta.size or 0
    offset = 0
    while offset < size:
        data = entry.read_random(offset, min(chunk_size, size - offset))
        if not data:
            break
        sha256.update(data)
        md5.update(data)
        offset += len(data)
    return sha256.hexdigest(), md5.hexdigest()

def detect_type(entry):
    try:
        data = entry.read_random(0, min(4096, entry.info.meta.size or 0))
        if not data:
            return "unknown"
        return MAGIC.from_buffer(data)
    except Exception:
        return "unknown"

def walk_and_collect(image_path, allowed_types, out_csv, registry_output_json, max_files=None):
    img, offset = open_image(image_path)
    fs = pytsk3.FS_Info(img, offset=offset)
    root = fs.open_dir(path="/")
    rows, registries = [], []
    usb_history = []
    count = 0

    REGISTRY_PATHS = [
        "/Windows/System32/config/SYSTEM"
    ]

    def parse_system_hive(entry):
        try:
            data = b""
            offset = 0
            while offset < entry.info.meta.size:
                chunk = entry.read_random(offset, 1024*1024)
                if not chunk:
                    break
                data += chunk
                offset += len(chunk)

            reg = Registry.Registry(io.BytesIO(data))
            usb_key_path = r"ControlSet001\Enum\USBSTOR"
            try:
                key = reg.open(usb_key_path)
                for subkey in key.subkeys():
                    device_name = subkey.name()
                    for instance in subkey.subkeys():
                        values = {v.name(): v.value() for v in instance.values()}
                        usb_history.append({
                            "device_name": device_name,
                            "instance": instance.name(),
                            "values": values
                        })
            except Registry.RegistryKeyNotFoundException:
                pass
        except Exception as e:
            print(f"[!] Error parsing SYSTEM hive: {e}")

    def _walk(dirobj, parent="/"):
        nonlocal count
        for entry in dirobj:
            try:
                name = entry.info.name.name.decode(errors='ignore')
                if name in (".", ".."):
                    continue
            except Exception:
                continue

            meta = getattr(entry.info, "meta", None)
            if not meta:
                continue

            fullpath = f"{parent.rstrip('/')}/{name}"

            if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    _walk(entry.as_directory(), fullpath)
                except Exception:
                    pass
                continue

            if meta.type != pytsk3.TSK_FS_META_TYPE_REG or meta.size <= 0:
                continue

            if fullpath == REGISTRY_PATHS[0]:
                parse_system_hive(entry)
                registries.append({"path": fullpath, "size": meta.size})
                continue

            ftype = detect_type(entry)

            if allowed_types and not any(ftype.startswith(t) for t in allowed_types):
                continue

            try:
                sha256, md5 = hash_file(entry)
                rows.append({
                    "path": fullpath,
                    "size": meta.size,
                    "mtime": getattr(meta, "mtime", None),
                    "ftype": ftype,
                    "sha256": sha256,
                    "md5": md5,
                    "deleted": False
                })
                count += 1
                if max_files and count >= max_files:
                    return
            except Exception:
                pass

    def _walk_deleted(dirobj, parent="/"):
        nonlocal count
        for entry in dirobj:
            try:
                name = entry.info.name.name.decode(errors='ignore')
                if name in (".", ".."):
                    continue
            except Exception:
                continue

            meta = getattr(entry.info, "meta", None)
            if not meta:
                continue

            if meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC:
                fullpath = f"{parent.rstrip('/')}/{name} (deleted)"
                ftype = detect_type(entry)

                if allowed_types and not any(ftype.startswith(t) for t in allowed_types):
                    continue

                try:
                    sha256, md5 = hash_file(entry)
                    rows.append({
                        "name": fullpath,
                        "size": meta.size,
                        "mtime": getattr(meta, "mtime", None),
                        "ftype": ftype,
                        "sha256": sha256,
                        "md5": md5,
                        "deleted": True
                    })
                    count += 1
                    if max_files and count >= max_files:
                        return
                except Exception:
                    pass

            # Recurse into directories even if deleted
            if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    _walk_deleted(entry.as_directory(), f"{parent.rstrip('/')}/{name}")
                except Exception:
                    pass

    _walk(root, "/")
    _walk_deleted(root, "/")

    df = pd.DataFrame(rows)
    df.to_csv(out_csv, index=False)

    with open(registry_output_json, "w") as f:
        json.dump({"usb_history": usb_history, "registries": registries}, f, indent=2)

    return df, registries, usb_history
