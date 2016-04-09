package com.netvirt.netvirt;

import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.util.Log;
import com.netvirt.netvirt.ToyVpnService;


public class NetvirtAgent extends org.qtproject.qt5.android.bindings.QtActivity
{
    private static String mServerAddress;
    private static String mServerPort;
    private static String mSharedSecret;
    private static NetvirtAgent mInstance;

    public NetvirtAgent()
    {
        mInstance = this;
    }

    public static void connect(String host, String port, String secret)
    {
        mServerAddress = host;
        mServerPort = port;
        mSharedSecret = secret;

        Intent intent = VpnService.prepare(mInstance);
        if (intent != null) {
            mInstance.startActivityForResult(intent, 0);
        } else {
            mInstance.onActivityResult(0, RESULT_OK, null);
        }
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        if (result == RESULT_OK) {
            String prefix = getPackageName();
            Intent intent = new Intent(this, ToyVpnService.class)
                .putExtra(prefix + ".ADDRESS", mServerAddress)
                .putExtra(prefix + ".PORT", mServerPort)
                .putExtra(prefix + ".SECRET", mSharedSecret);
            startService(intent);
        }
    }
}
