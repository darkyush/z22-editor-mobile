[app]
title = Z22 Editor
package.name = z22editor
package.domain = org.z22
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,z22
version = 1.0
requirements = python3,kivy,cryptography,android
orientation = portrait
android.api = 30
# پشتیبانی از هر دو معماری اصلی گوشی‌ها
android.archs = arm64-v8a, armeabi-v7a
android.permissions = READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE
icon.filename = %(source.dir)s/icon.png

[buildozer]
log_level = 2
warn_on_root = 1