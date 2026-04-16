package com.theodore.auth.server.utils;

import java.util.List;

public class PermissionsPolicy {

    private PermissionsPolicy() {
    }

    public static String buildPermissionsPolicy() {
        return String.join(", ", List.of(
                "accelerometer=()",
                "ambient-light-sensor=()",
                "autoplay=()",
                "battery=()",
                "camera=()",
                "display-capture=()",
                "document-domain=()",
                "encrypted-media=()",
                "fullscreen=()",
                "gamepad=()",
                "geolocation=()",
                "gyroscope=()",
                "hid=()",
                "idle-detection=()",
                "local-fonts=()",
                "magnetometer=()",
                "microphone=()",
                "midi=()",
                "otp-credentials=()",
                "payment=()",
                "picture-in-picture=()",
                "publickey-credentials-create=()",
                "publickey-credentials-get=()",
                "screen-wake-lock=()",
                "serial=()",
                "speaker-selection=()",
                "storage-access=()",
                "usb=()",
                "web-share=()",
                "window-management=()",
                "xr-spatial-tracking=()"
        ));
    }

}
