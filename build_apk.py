#!/usr/bin/env python3
"""
build_apk.py — Builds polytracker-debug.apk without Android SDK.

Implements from scratch:
  1. Dalvik DEX bytecode  (classes.dex)
  2. Android Binary XML   (AndroidManifest.xml)
  3. Binary Resource Table (resources.arsc)
  4. APK zip packaging + jarsigner

The resulting APK contains a single Activity that loads
  file:///android_asset/index.html  in a JavaScript-enabled WebView.
"""

import struct, zlib, hashlib, zipfile, os, subprocess, sys, shutil, tempfile
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# DEX builder — hand-crafted minimal classes.dex
# ─────────────────────────────────────────────────────────────────────────────

def u8(v):  return struct.pack('<B', v & 0xFF)
def u16(v): return struct.pack('<H', v & 0xFFFF)
def u32(v): return struct.pack('<I', v & 0xFFFFFFFF)

def uleb128(value):
    """Encode unsigned LEB128."""
    out = []
    while True:
        b = value & 0x7F
        value >>= 7
        if value != 0:
            b |= 0x80
        out.append(b)
        if value == 0:
            break
    return bytes(out)

def sleb128(value):
    """Encode signed LEB128."""
    out = []
    more = True
    while more:
        b = value & 0x7F
        value >>= 7
        if (value == 0 and (b & 0x40) == 0) or (value == -1 and (b & 0x40) != 0):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)


# ─────────────────────────────────────────────────────────────────────────────
# Android Binary XML (AXML) format
# Used for: AndroidManifest.xml, res/layout/*.xml
# Format reference: https://github.com/androguard/androguard (axml.py)
# ─────────────────────────────────────────────────────────────────────────────

RES_NULL_TYPE              = 0x0000
RES_STRING_POOL_TYPE       = 0x0001
RES_TABLE_TYPE             = 0x0002
RES_XML_TYPE               = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE   = 0x0101
RES_XML_START_ELEMENT_TYPE   = 0x0102
RES_XML_END_ELEMENT_TYPE     = 0x0103
RES_XML_CDATA_TYPE           = 0x0104

# res value types
TYPE_STRING   = 0x03
TYPE_INT_DEC  = 0x10
TYPE_INT_BOOL = 0x12
TYPE_INT_HEX  = 0x11
TYPE_REFERENCE = 0x01

ANDROID_NS = "http://schemas.android.com/apk/res/android"

def encode_string_pool(strings):
    """Encode UTF-16 string pool (style-less)."""
    # Header:
    #   chunk_type  u16 = 0x0001
    #   header_size u16 = 0x001C
    #   chunk_size  u32
    #   string_count u32
    #   style_count  u32 = 0
    #   flags        u32  (bit0=sorted, bit8=UTF8)
    #   strings_start u32 (offset from chunk start to string data)
    #   styles_start  u32 = 0
    #   offsets[string_count]  u32 each
    #   string data (UTF-16LE with 2-byte length prefix + 2-byte null terminator)

    count = len(strings)
    header_size = 0x1C
    offsets_size = count * 4

    # Build string data (UTF-16LE each, preceded by uint16 length, followed by uint16 null)
    string_data = b''
    offsets = []
    for s in strings:
        offsets.append(len(string_data))
        enc = s.encode('utf-16-le')
        length_in_chars = len(s)
        string_data += struct.pack('<H', length_in_chars) + enc + b'\x00\x00'

    strings_start = header_size + offsets_size
    chunk_size = strings_start + len(string_data)

    blob = struct.pack('<HHIIIIII',
        RES_STRING_POOL_TYPE, header_size,
        chunk_size,
        count, 0,    # string_count, style_count
        0,           # flags (UTF-16)
        strings_start, 0)  # strings_start, styles_start

    for off in offsets:
        blob += struct.pack('<I', off)
    blob += string_data
    return blob


class AXMLWriter:
    """Builds an Android Binary XML document."""

    def __init__(self):
        self.strings = []
        self._str_idx = {}
        self.chunks = []

    def _str(self, s):
        if s not in self._str_idx:
            self._str_idx[s] = len(self.strings)
            self.strings.append(s)
        return self._str_idx[s]

    def _ns(self, uri):
        return self._str(uri) if uri else 0xFFFFFFFF

    def start_ns(self, prefix, uri):
        pi = self._str(prefix)
        ui = self._str(uri)
        data = struct.pack('<IIII', 1, 0, pi, ui)    # line, comment=-1 actually
        self.chunks.append((RES_XML_START_NAMESPACE_TYPE, data))

    def end_ns(self, prefix, uri):
        pi = self._str(prefix)
        ui = self._str(uri)
        data = struct.pack('<IIII', 1, 0xFFFFFFFF, pi, ui)
        self.chunks.append((RES_XML_END_NAMESPACE_TYPE, data))

    def start_element(self, ns, name, attrs):
        """attrs: list of (ns_uri, name, value, res_id, value_type)"""
        ns_i   = self._ns(ns)
        name_i = self._str(name)
        attr_count = len(attrs)
        attr_size = 0x14  # 20 bytes per attr

        # encode attributes
        attr_data = b''
        for (ans, aname, aval, res_id, vtype) in attrs:
            ans_i   = self._ns(ans)
            aname_i = self._str(aname)
            # raw value string index (0xFFFFFFFF if not string)
            if isinstance(aval, str):
                aval_i = self._str(aval)
                raw_val = aval_i
                typed_val = aval_i
                act_type = TYPE_STRING
            else:
                raw_val = 0xFFFFFFFF
                typed_val = aval
                act_type = vtype

            attr_data += struct.pack('<IIIIBBHI',
                ans_i, aname_i, raw_val,
                8,          # size of typed_value (always 8)
                0,          # res0
                act_type,   # dataType
                0,          # padding
                typed_val)  # data

        header = struct.pack('<IIHHHHH',
            1, 0xFFFFFFFF,   # line, comment
            ns_i & 0xFFFF, name_i & 0xFFFF,  # only low 16 bits needed? no use full
            0x14,            # attr_start (offset to first attr from element start = 20)
            attr_size,       # attr_size (20 bytes each)
            attr_count,      # attr_count
        )
        # Actually the element header is fixed: line(4) comment(4) ns(4) name(4) attrStart(2) attrSize(2) attrCount(2) idIndex(2) classIndex(2) styleIndex(2)
        header = struct.pack('<iiiiHHHHHH',
            1, -1,
            ns_i if ns else -1, name_i,
            0x14, attr_size, attr_count,
            0, 0, 0)   # id/class/style attr indices (0=none)
        self.chunks.append((RES_XML_START_ELEMENT_TYPE, header + attr_data))

    def end_element(self, ns, name):
        ns_i   = self._ns(ns) if ns else 0xFFFFFFFF
        name_i = self._str(name)
        data = struct.pack('<iiII', 1, -1, ns_i, name_i)
        self.chunks.append((RES_XML_END_ELEMENT_TYPE, data))

    def build(self):
        # Build string pool first (need all strings registered)
        str_pool = encode_string_pool(self.strings)

        # Build each chunk
        chunks_data = b''
        for (chunk_type, payload) in self.chunks:
            header_size = 8
            chunk_size = header_size + len(payload)
            chunks_data += struct.pack('<HHI', chunk_type, header_size, chunk_size)
            chunks_data += payload

        # Outer RES_XML header
        inner = str_pool + chunks_data
        outer_header = struct.pack('<HHI', RES_XML_TYPE, 8, 8 + len(inner))
        return outer_header + inner


def build_manifest():
    """Build binary AndroidManifest.xml."""
    w = AXMLWriter()

    # Namespace
    w.start_ns("android", ANDROID_NS)

    # <manifest package="com.polymarket.watcher" versionCode="1" versionName="1.0">
    def A(name): return ANDROID_NS
    w.start_element(None, "manifest", [
        (None,        "package",     "com.polymarket.watcher", 0, TYPE_STRING),
        (ANDROID_NS,  "versionCode", 1,   0x0101021B, TYPE_INT_DEC),
        (ANDROID_NS,  "versionName", "1.0.0", 0x0101021C, TYPE_STRING),
    ])

    # <uses-permission android:name="android.permission.INTERNET"/>
    w.start_element(None, "uses-permission", [
        (ANDROID_NS, "name", "android.permission.INTERNET", 0x01010003, TYPE_STRING),
    ])
    w.end_element(None, "uses-permission")

    # <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
    w.start_element(None, "uses-permission", [
        (ANDROID_NS, "name", "android.permission.ACCESS_NETWORK_STATE", 0x01010003, TYPE_STRING),
    ])
    w.end_element(None, "uses-permission")

    # <application android:label="PolyTracker" android:hardwareAccelerated="true">
    w.start_element(None, "application", [
        (ANDROID_NS, "label",                "PolyTracker",  0x01010001, TYPE_STRING),
        (ANDROID_NS, "hardwareAccelerated",  1, 0x0101028F, TYPE_INT_BOOL),
        (ANDROID_NS, "usesCleartextTraffic", 0, 0x010104EC, TYPE_INT_BOOL),
        (ANDROID_NS, "allowBackup",          0, 0x01010280, TYPE_INT_BOOL),
    ])

    # <activity android:name=".MainActivity" android:exported="true">
    w.start_element(None, "activity", [
        (ANDROID_NS, "name",     "com.polymarket.watcher.MainActivity", 0x01010003, TYPE_STRING),
        (ANDROID_NS, "exported", 1, 0x01010010, TYPE_INT_BOOL),
        (ANDROID_NS, "configChanges", 0x000000FB, 0x0101001F, TYPE_INT_HEX),
    ])

    # <intent-filter>
    w.start_element(None, "intent-filter", [])

    # <action android:name="android.intent.action.MAIN"/>
    w.start_element(None, "action", [
        (ANDROID_NS, "name", "android.intent.action.MAIN", 0x01010003, TYPE_STRING),
    ])
    w.end_element(None, "action")

    # <category android:name="android.intent.category.LAUNCHER"/>
    w.start_element(None, "category", [
        (ANDROID_NS, "name", "android.intent.category.LAUNCHER", 0x01010003, TYPE_STRING),
    ])
    w.end_element(None, "category")

    w.end_element(None, "intent-filter")
    w.end_element(None, "activity")
    w.end_element(None, "application")
    w.end_element(None, "manifest")

    w.end_ns("android", ANDROID_NS)

    return w.build()


# ─────────────────────────────────────────────────────────────────────────────
# Minimal resources.arsc  (just a string pool with app_name)
# ─────────────────────────────────────────────────────────────────────────────

def build_resources_arsc():
    """Build a minimal resources.arsc binary file."""
    # A proper resources.arsc is complex.
    # We'll emit a minimal table with one package (com.polymarket.watcher)
    # and one string resource: string/app_name = "PolyTracker"
    # Resource ID 0x7F040000

    # String pool for global strings (value strings)
    value_strings = ["PolyTracker"]
    val_pool = encode_string_pool(value_strings)

    # String pool for type strings
    type_strings = ["string"]
    type_pool = encode_string_pool(type_strings)

    # String pool for key strings (resource names)
    key_strings = ["app_name"]
    key_pool = encode_string_pool(key_strings)

    # RES_TABLE_TYPE_SPEC (specifies config flags per entry)
    # Just one entry with flags = 0
    spec_payload = struct.pack('<I', 1)  # entryCount
    spec_payload += struct.pack('<I', 0) # flags for entry 0
    # header: chunk_type=0x0202, header_size=0x1C, chunk_size, id, flags, entryCount
    spec_header = struct.pack('<HHIBBHI',
        0x0202,  # RES_TABLE_TYPE_SPEC_TYPE
        0x1C,    # header_size
        0x1C + len(spec_payload),
        1,       # id (type index, 1-based) = 1 for "string"
        0, 0,    # res0, res1
        1)       # entryCount
    spec_chunk = spec_header + spec_payload

    # RES_TABLE_TYPE (actual entries for default config)
    # Config size = 32 bytes (minimal)
    config = b'\x20\x00\x00\x00' + b'\x00' * 28  # size=32, rest=0 (default config)
    entries_start = 52  # offset from chunk start to entries section (header_size + entryCount*4)
    entry_offsets = struct.pack('<I', 0)  # one entry at offset 0
    # ResTable_entry (8 bytes): size, flags, key
    # Res_value (8 bytes): size, res0, dataType, data
    entry_data = struct.pack('<HHIHBBI',
        8,           # entry.size (ResTable_entry = 8: 2+2+4)
        0,           # entry.flags (0=simple)
        0,           # entry.key index (app_name = 0 in key_pool)
        8,           # value.size (Res_value = 8)
        0,           # value.res0
        TYPE_STRING, # value.dataType
        0)           # value.data (index 0 in value_strings = "PolyTracker")

    type_payload = config + entry_offsets + entry_data
    type_header_size = 52  # standard
    type_chunk = struct.pack('<HHIBBHII',
        0x0201,           # RES_TABLE_TYPE_TYPE
        type_header_size,
        type_header_size + len(type_payload),
        1,  # id (type index)
        0, 0,   # res0, res1
        1,      # entryCount
        entries_start,    # entriesStart (offset from chunk start)
    ) + type_payload

    # RES_TABLE_PACKAGE
    pkg_strings = type_pool + key_pool + spec_chunk + type_chunk
    type_strings_offset = 288  # header size of package
    key_strings_offset = type_strings_offset + len(type_pool)
    # package name is a 256-byte UTF-16 field
    pkg_name = "com.polymarket.watcher".encode('utf-16-le')[:254] + b'\x00\x00'
    pkg_name = pkg_name.ljust(256, b'\x00')
    pkg_header = struct.pack('<HHI', 0x0200, 288, 288 + len(pkg_strings))
    pkg_header += struct.pack('<I', 0x7F)  # id
    pkg_header += pkg_name                  # name (256 bytes)
    pkg_header += struct.pack('<IIII',
        type_strings_offset,   # typeStrings
        0,                      # lastPublicType
        key_strings_offset,    # keyStrings
        0)                      # lastPublicKey
    # Pad to 288 bytes
    pkg_header = pkg_header.ljust(288, b'\x00')
    pkg_chunk = pkg_header + pkg_strings

    # Global string pool (resource value strings)
    global_pool = val_pool

    # Root RES_TABLE_TYPE header
    total = 8 + 4 + len(global_pool) + len(pkg_chunk)
    root = struct.pack('<HHII',
        0x0002,  # RES_TABLE_TYPE
        8 + 4,   # header_size (includes packageCount field)
        total,
        1)       # packageCount

    return root + global_pool + pkg_chunk


# ─────────────────────────────────────────────────────────────────────────────
# DEX builder — minimal classes.dex for a WebView Activity
# ─────────────────────────────────────────────────────────────────────────────
# We'll produce a hand-crafted DEX that implements:
#
#   package com.polymarket.watcher;
#   import android.app.Activity;
#   import android.os.Bundle;
#   import android.webkit.*;
#
#   public class MainActivity extends Activity {
#     WebView wv;
#     public void onCreate(Bundle b) {
#       super.onCreate(b);
#       wv = new WebView(this);
#       WebSettings ws = wv.getSettings();
#       ws.setJavaScriptEnabled(true);
#       ws.setDomStorageEnabled(true);
#       ws.setAllowUniversalAccessFromFileURLs(true);
#       ws.setAllowFileAccessFromFileURLs(true);
#       setContentView(wv);
#       wv.loadUrl("file:///android_asset/index.html");
#     }
#     public void onBackPressed() {
#       if (wv != null && wv.canGoBack()) wv.goBack();
#       else super.onBackPressed();
#     }
#   }
#
# Building DEX manually is complex. Instead we use smali assembly language
# and produce the dex via the smali jar we downloaded, OR we write the
# bytes directly.
#
# APPROACH: Write smali files, then run smali-2.5.2.jar to assemble to DEX.

SMALI_CODE = r"""
.class public Lcom/polymarket/watcher/MainActivity;
.super Landroid/app/Activity;
.source "MainActivity.kt"

.field private wv:Landroid/webkit/WebView;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .registers 6

    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    new-instance v0, Landroid/webkit/WebView;
    invoke-direct {v0, p0}, Landroid/webkit/WebView;-><init>(Landroid/content/Context;)V
    iput-object v0, p0, Lcom/polymarket/watcher/MainActivity;->wv:Landroid/webkit/WebView;

    invoke-virtual {v0}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;
    move-result-object v1

    const/4 v2, 0x1

    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setDomStorageEnabled(Z)V
    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V
    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V

    invoke-virtual {p0, v0}, Landroid/app/Activity;->setContentView(Landroid/view/View;)V

    const-string v3, "file:///android_asset/index.html"
    invoke-virtual {v0, v3}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V

    return-void
.end method

.method public onBackPressed()V
    .registers 3

    iget-object v0, p0, Lcom/polymarket/watcher/MainActivity;->wv:Landroid/webkit/WebView;
    if-eqz v0, :super

    invoke-virtual {v0}, Landroid/webkit/WebView;->canGoBack()Z
    move-result v1
    if-eqz v1, :super

    invoke-virtual {v0}, Landroid/webkit/WebView;->goBack()V
    return-void

    :super
    invoke-super {p0}, Landroid/app/Activity;->onBackPressed()V
    return-void
.end method
"""

SMALI_RUNNER_SRC = """\
import org.jf.smali.Smali;
import org.jf.smali.SmaliOptions;
import java.util.Arrays;

public class SmaliRunner {
    public static void main(String[] args) throws Exception {
        SmaliOptions opts = new SmaliOptions();
        opts.apiLevel = 24;
        opts.outputDexFile = args[1];
        boolean ok = Smali.assemble(opts, Arrays.asList(args[0]));
        if (!ok) { System.err.println("ERROR"); System.exit(1); }
    }
}
"""

def _smali_classpath():
    """Return classpath string for smali invocation."""
    jars = [
        "/tmp/smali.jar",
        "/tmp/dexlib2-2.5.2.jar",
        "/tmp/util-2.5.2.jar",
        "/tmp/jcommander-1.72.jar",
        "/tmp/guava-30.1.1-jre.jar",
        "/tmp/antlr3-runtime.jar",
        "/tmp/ST4-4.3.1.jar",
    ]
    return ":".join(jars)

def _ensure_smali_runner(runner_dir):
    """Compile SmaliRunner.java if not already compiled."""
    runner_class = runner_dir / "SmaliRunner.class"
    if runner_class.exists():
        return
    src = runner_dir / "SmaliRunner.java"
    src.write_text(SMALI_RUNNER_SRC)
    cp = _smali_classpath()
    result = subprocess.run(
        ["javac", "-cp", cp, str(src), "-d", str(runner_dir)],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"SmaliRunner compile failed: {result.stderr[:500]}")

def build_dex(smali_jar, work_dir):
    """Write smali and assemble to DEX using smali library via a Java wrapper."""
    smali_dir = work_dir / "smali" / "com" / "polymarket" / "watcher"
    smali_dir.mkdir(parents=True, exist_ok=True)
    smali_file = smali_dir / "MainActivity.smali"
    smali_file.write_text(SMALI_CODE)

    # Ensure the SmaliRunner helper is compiled
    runner_dir = work_dir / "runner"
    runner_dir.mkdir(exist_ok=True)
    _ensure_smali_runner(runner_dir)

    dex_file = work_dir / "classes.dex"
    cp = str(runner_dir) + ":" + _smali_classpath()
    smali_input = str(smali_dir.parent.parent.parent)  # top of smali tree
    cmd = ["java", "-cp", cp, "SmaliRunner", smali_input, str(dex_file)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0 or not dex_file.exists():
        print("smali STDERR:", result.stderr[:2000])
        print("smali STDOUT:", result.stdout[:2000])
        raise RuntimeError("smali assembly failed")
    return dex_file


# ─────────────────────────────────────────────────────────────────────────────
# APK packaging and signing
# ─────────────────────────────────────────────────────────────────────────────

def generate_keystore(keystore_path):
    """Generate a debug keystore with keytool."""
    if keystore_path.exists():
        return
    cmd = [
        "keytool", "-genkey", "-v",
        "-keystore", str(keystore_path),
        "-storepass", "android",
        "-alias", "androiddebugkey",
        "-keypass", "android",
        "-keyalg", "RSA", "-keysize", "2048",
        "-validity", "10000",
        "-dname", "CN=Android Debug,O=Android,C=US"
    ]
    subprocess.run(cmd, check=True, capture_output=True)
    print(f"  Keystore generated: {keystore_path}")


def sign_apk(apk_path, keystore_path):
    """Sign the APK with jarsigner."""
    cmd = [
        "jarsigner",
        "-sigalg", "SHA256withRSA",
        "-digestalg", "SHA-256",
        "-keystore", str(keystore_path),
        "-storepass", "android",
        "-keypass", "android",
        str(apk_path),
        "androiddebugkey",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("jarsigner stderr:", result.stderr[:1000])
        raise RuntimeError("jarsigner failed")


def build_apk():
    project_root = Path(__file__).parent
    assets_dir   = project_root / "android" / "app" / "src" / "main" / "assets"
    icons_base   = project_root / "android" / "app" / "src" / "main" / "res"
    smali_jar    = Path("/tmp/smali.jar")
    keystore     = Path("/tmp/debug.keystore")
    output_apk   = project_root / "polytracker-debug.apk"

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        print("Step 1/5  Assembling DEX bytecode via smali...")
        dex_file = build_dex(smali_jar, work)
        print(f"  classes.dex: {dex_file.stat().st_size} bytes")

        print("Step 2/5  Building binary AndroidManifest.xml...")
        manifest_data = build_manifest()
        print(f"  AndroidManifest.xml: {len(manifest_data)} bytes")

        print("Step 3/5  Building resources.arsc...")
        res_data = build_resources_arsc()
        print(f"  resources.arsc: {len(res_data)} bytes")

        print("Step 4/5  Packaging APK zip...")
        with zipfile.ZipFile(str(output_apk), 'w', zipfile.ZIP_DEFLATED) as apk:
            # Manifest (stored, not deflated — Android requires it stored for fast access)
            apk.write(str(dex_file), "classes.dex")
            apk.writestr(zipfile.ZipInfo("AndroidManifest.xml"), manifest_data)
            apk.writestr(zipfile.ZipInfo("resources.arsc"), res_data)

            # Web app assets
            index_html = assets_dir / "index.html"
            if index_html.exists():
                apk.write(str(index_html), "assets/index.html")
                print(f"  assets/index.html: {index_html.stat().st_size} bytes")
            else:
                print("  WARNING: assets/index.html not found, APK will be incomplete")

            # Launcher icons
            icon_sizes = {
                "mipmap-mdpi":    "mdpi",
                "mipmap-hdpi":    "hdpi",
                "mipmap-xhdpi":   "xhdpi",
                "mipmap-xxhdpi":  "xxhdpi",
                "mipmap-xxxhdpi": "xxxhdpi",
            }
            for folder, _ in icon_sizes.items():
                for icon in ["ic_launcher.png", "ic_launcher_round.png"]:
                    src = icons_base / folder / icon
                    if src.exists():
                        apk.write(str(src), f"res/{folder}/{icon}")

        print("Step 5/5  Signing APK with debug certificate...")
        generate_keystore(keystore)
        sign_apk(output_apk, keystore)
        size_kb = output_apk.stat().st_size // 1024
        print(f"\n  ✓  APK built: {output_apk}  ({size_kb} KB)")

    return output_apk


if __name__ == "__main__":
    print("=== PolyTracker APK Builder ===\n")
    try:
        apk = build_apk()
        print(f"\nSuccess! Install on device with:")
        print(f"  adb install {apk}")
        print(f"Or transfer {apk.name} to your Android device and open it.")
    except Exception as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        import traceback; traceback.print_exc()
        sys.exit(1)
