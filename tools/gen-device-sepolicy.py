#!/usr/bin/env python3
"""Derive a device's sepolicy set from another device's generated files.

Contexts cannot be merged between devices, so each device tree carries its own
generated set. Rather than redo the whole recovery per device, this applies the
measured difference between two stock policies to an existing generated set:
context entries are keyed (path, property prefix, fs+path, service name) and the
output takes its keys from the reference set plus the new device's stock, with
every value read from the new device's stock. The .te files drop rules naming
types the new device does not declare and gain declarations and rules for the
types it adds, attributes taken from its own compiled policy.

Usage, from the tree root:
    tools/gen-device-sepolicy.py <new-device> <reference-device>

Expects both devices' stock images extracted under scratch/famrecon/<device>/.
"""

import os
import re
import sys

FAMRECON = os.path.expanduser("~/Projects/yogi/scratch/famrecon")

VENDOR_CONTEXTS = [
    "file_contexts",
    "property_contexts",
    "service_contexts",
    "hwservice_contexts",
    "vndservice_contexts",
]
PRIVATE_CONTEXTS = [
    "property_contexts",
    "file_contexts",
    "service_contexts",
]

VERSIONED = re.compile(r"_\d{6}$")


def stock_paths(dev):
    v = os.path.join(FAMRECON, dev, "vendor/etc/selinux")
    p = os.path.join(FAMRECON, dev, "system_ext/etc/selinux")
    return v, p


def stock_name(partition, name):
    prefix = "system_ext_" if partition == "private" else "vendor_"
    if name in ("file_contexts", "property_contexts", "service_contexts",
                "hwservice_contexts", "seapp_contexts"):
        return prefix + name
    return name


def load_lines(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return [l.rstrip("\n") for l in f]


def key_of(line, name):
    fields = line.split()
    if not fields or line.startswith("#"):
        return None
    if name == "genfs_contexts":
        return tuple(fields[1:3])
    return fields[0]


def transform_contexts(ref_generated, ref_stock, dev_stock, name):
    ref_keys = {}
    for line in ref_generated:
        k = key_of(line, name)
        if k is not None:
            ref_keys[k] = line
    dev_map = {}
    for line in dev_stock:
        k = key_of(line, name)
        if k is not None:
            dev_map[k] = line
    ref_stock_keys = set()
    for line in ref_stock or []:
        k = key_of(line, name)
        if k is not None:
            ref_stock_keys.add(k)
    out, added, dropped = [], [], []
    for line in ref_generated:
        k = key_of(line, name)
        if k is None:
            out.append(line)
        elif k in dev_map:
            out.append(dev_map[k])
        else:
            dropped.append(line)
    for k in sorted(dev_map, key=str):
        if k not in ref_keys and k not in ref_stock_keys:
            added.append(dev_map[k])
            out.append(dev_map[k])
    return out, added, dropped


def cil_types(cil):
    return set(re.findall(r"^\(type ([A-Za-z0-9_-]+)\)", cil, re.M))


def cil_attrs_for(cil, types):
    attrs = {t: set() for t in types}
    for m in re.finditer(r"^\(typeattributeset ([A-Za-z0-9_.-]+) \(([^)]*)\)", cil, re.M):
        attr, members = m.group(1), m.group(2).split()
        for t in types:
            if t in members and not attr.startswith("base_typeattr"):
                attrs[t].add(attr)
    return attrs


def cil_rules_for(cil, types):
    rule = re.compile(
        r"^\((allow|dontaudit)\s+([A-Za-z0-9_-]+)\s+([A-Za-z0-9_-]+)"
        r"\s+\(([a-z0-9_]+)\s+\(([a-z0-9_ ]+)\)\)\)$", re.M)
    out = []
    for kind, s, t, cls, perms in rule.findall(cil):
        names = {s, t}
        if not names & types:
            continue
        out.append((kind, s, t, cls, sorted(perms.split())))
    return out


def deversion(name, vocab):
    if name == "self":
        return "self"
    if name in vocab:
        return name
    base = VERSIONED.sub("", name)
    return base if base in vocab else None


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    dev, ref = sys.argv[1], sys.argv[2]
    tree = os.path.expanduser("~/Projects/yogi/lineage/device/google")
    ref_sep = os.path.join(tree, ref, "sepolicy")
    dev_sep = os.path.join(tree, dev, "sepolicy")

    rv, rp = stock_paths(ref)
    dv, dp = stock_paths(dev)
    ref_cil = open(os.path.join(rv, "vendor_sepolicy.cil")).read()
    dev_cil = open(os.path.join(dv, "vendor_sepolicy.cil")).read()

    ref_types = cil_types(ref_cil)
    dev_types = cil_types(dev_cil)
    # Only consider types our reference tree declares itself; AOSP types sit in
    # both cils and fall outside the diff.
    ours = set()
    for name in ("device_types.te", "genfs_types.te", "device_domains.te"):
        body = open(os.path.join(ref_sep, "vendor", name)).read()
        ours |= set(re.findall(r"^\s*type ([A-Za-z0-9_-]+)", body, re.M))
    dropped = sorted(t for t in ours if t in ref_types and t not in dev_types)
    added = sorted(t for t in dev_types - ref_types if not t.startswith("base_typeattr"))
    if len(dropped) > 40 or len(added) > 40:
        sys.exit(f"implausible delta, refusing: dropped {dropped}, added {added}")
    print(f"types dropped: {dropped}")
    print(f"types added:   {added}")

    drop_re = re.compile(r"\b(%s)\b" % "|".join(dropped)) if dropped else None

    # seapp_contexts are hand-curated (apps re-signed here need their entries
    # adjusted), so they are copied from the reference rather than derived; the
    # entries match on several attributes and the app set is family-wide.
    for part in ("vendor", "private"):
        os.makedirs(os.path.join(dev_sep, part), exist_ok=True)
        src = os.path.join(ref_sep, part, "seapp_contexts")
        if os.path.exists(src):
            with open(src) as f, open(os.path.join(dev_sep, part, "seapp_contexts"), "w") as g:
                g.write(f.read())

    # Vendor and private contexts.
    for part, names, stock_dir_r, stock_dir_d in (
        ("vendor", VENDOR_CONTEXTS, rv, dv),
        ("private", PRIVATE_CONTEXTS, rp, dp),
    ):
        for name in names:
            gen = load_lines(os.path.join(ref_sep, part, name))
            if gen is None:
                continue
            rstock = load_lines(os.path.join(stock_dir_r, stock_name(part, name))) or []
            dstock = load_lines(os.path.join(stock_dir_d, stock_name(part, name))) or []
            out, added_l, dropped_l = transform_contexts(gen, rstock, dstock, name)
            with open(os.path.join(dev_sep, part, name), "w") as f:
                f.write("\n".join(out) + "\n")
            print(f"{part}/{name}: {len(out)} lines, +{len(added_l)} -{len(dropped_l)}")
            for l in added_l:
                print(f"    + {l}")

    # genfs_contexts: keyed on fs and path. Excluded keys are those the tree
    # labels itself (a duplicate fs and path pair is a hard checkpolicy error),
    # not what the reference stock carries: the reference file predates stock
    # entries the tree still does not cover, and those have to carry over.
    gen = load_lines(os.path.join(ref_sep, "vendor/genfs_contexts"))

    def genfs_from_cil(cil):
        out = []
        for fs, path_, ctx in re.findall(
                r'^\(genfscon\s+(\S+)\s+"([^"]+)"\s+\(u object_r (\S+) ',
                cil, re.M):
            out.append(f"genfscon {fs} {path_} u:object_r:{ctx}:s0")
        return out

    TREE_GENFS = [
        "system/sepolicy/private/genfs_contexts",
        "system/sepolicy/vendor/genfs_contexts",
        "device/lineage/sepolicy/common/private/genfs_contexts",
        "device/lineage/sepolicy/common/dynamic/genfs_contexts",
    ] + [
        "hardware/google/pixel-sepolicy/" + d + "/genfs_contexts"
        for d in ("citadel", "power-libperfmgr", "powerstats", "sscoredump",
                  "lineage_health", "powershare", "touch", "wifi_ext")
    ]
    covered = set()
    for f in TREE_GENFS:
        p = os.path.join(os.path.expanduser("~/Projects/yogi/lineage"), f)
        if os.path.exists(p):
            for line in open(p):
                fields = line.split()
                if fields and not line.startswith("#"):
                    covered.add(tuple(fields[1:3]))

    # Reuse transform_contexts with the tree-covered set standing in for the
    # reference stock: a key is new only if nothing labels it.
    out, added_l, dropped_l = transform_contexts(
        gen,
        [f"genfscon {k[0]} {k[1]} placeholder" for k in covered],
        genfs_from_cil(dev_cil),
        "genfs_contexts")
    with open(os.path.join(dev_sep, "vendor/genfs_contexts"), "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"vendor/genfs_contexts: {len(out)} lines, +{len(added_l)} -{len(dropped_l)}")
    for l in added_l:
        print(f"    + {l}")

    # Domains first: a type with an init transition is a domain and is declared
    # in device_domains.te, everything else in device_types.te.
    dom_added = [t for t in added
                 if re.search(r"\(typetransition init\S* %s_exec " % t, dev_cil)]

    # Type declarations.
    attrs = cil_attrs_for(dev_cil, added)
    for name in ("device_types.te", "genfs_types.te"):
        src = os.path.join(ref_sep, "vendor", name)
        lines = open(src).read().splitlines()
        out = [l for l in lines if not (drop_re and drop_re.search(l))]
        with open(os.path.join(dev_sep, "vendor", name), "w") as f:
            f.write("\n".join(out) + "\n")
    with open(os.path.join(dev_sep, "vendor/device_types.te"), "a") as f:
        f.write("\n# Added for this device, attributes from its own compiled policy.\n")
        for t in added:
            if t in dom_added:
                continue
            a = sorted(attrs[t])
            f.write("type %s%s;\n" % (t, ", " + ", ".join(a) if a else ""))

    dom = open(os.path.join(ref_sep, "vendor/device_domains.te")).read().splitlines()
    out = [l for l in dom if not (drop_re and drop_re.search(l))]
    with open(os.path.join(dev_sep, "vendor/device_domains.te"), "w") as f:
        f.write("\n".join(out) + "\n")
        for t in dom_added:
            f.write(f"\ntype {t}, domain;\ninit_daemon_domain({t})\n")
    print(f"domains added: {dom_added}")

    # Allow and dontaudit rules.
    vocab = set(re.findall(r"[A-Za-z0-9_-]+", open(
        os.path.join(ref_sep, "vendor/device_allow.te")).read()))
    for t in added:
        vocab.add(t)
    for src_name in ("device_allow.te", "device_dontaudit.te", "device_residual.te"):
        src = os.path.join(ref_sep, "vendor", src_name)
        if not os.path.exists(src):
            continue
        lines = open(src).read().splitlines()
        out = [l for l in lines if not (drop_re and drop_re.search(l))]
        with open(os.path.join(dev_sep, "vendor", src_name), "w") as f:
            f.write("\n".join(out) + "\n")
    rules = cil_rules_for(dev_cil, set(added))
    with open(os.path.join(dev_sep, "vendor/device_allow.te"), "a") as f:
        f.write("\n# Added for this device, from its own compiled policy.\n")
        for kind, s, t, cls, perms in rules:
            if kind != "allow":
                continue
            s2, t2 = deversion(s, vocab), deversion(t, vocab)
            if s2 is None or t2 is None:
                print(f"    skipped {kind} {s} {t} (unknown name)")
                continue
            f.write("allow %s %s:%s { %s };\n" % (s2, t2, cls, " ".join(perms)))
    with open(os.path.join(dev_sep, "vendor/device_dontaudit.te"), "a") as f:
        wrote = False
        for kind, s, t, cls, perms in rules:
            if kind != "dontaudit":
                continue
            s2, t2 = deversion(s, vocab), deversion(t, vocab)
            if s2 is None or t2 is None:
                continue
            if not wrote:
                f.write("\n# Added for this device, from its own compiled policy.\n")
                wrote = True
            f.write("dontaudit %s %s:%s { %s };\n" % (s2, t2, cls, " ".join(perms)))

    # The drop file is build-harvested and device-independent.
    drop = os.path.join(ref_sep, "vendor/device_allow.drop")
    if os.path.exists(drop):
        lines = open(drop).read().splitlines()
        out = [l for l in lines if not (drop_re and drop_re.search(l))]
        with open(os.path.join(dev_sep, "vendor/device_allow.drop"), "w") as g:
            g.write("\n".join(out) + "\n")

    # Verify no dropped type is still referenced anywhere in the new tree.
    leftover = []
    for root, _, files in os.walk(dev_sep):
        for fn in files:
            p = os.path.join(root, fn)
            if drop_re and drop_re.search(open(p).read()):
                leftover.append(p)
    if leftover:
        sys.exit("dropped types still referenced: %s" % leftover)
    print("done")


main()
