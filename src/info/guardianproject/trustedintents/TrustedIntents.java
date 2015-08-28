
package info.guardianproject.trustedintents;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.LabeledIntent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.pm.ResolveInfo;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Parcelable;
import android.text.TextUtils;

import java.lang.reflect.Constructor;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

public class TrustedIntents {

    private static TrustedIntents instance;

    private static Context context;
    private static PackageManager pm;

    private final LinkedHashSet<ApkSignaturePin> pinList;

    private TrustedIntents(Context c) {
        context = c.getApplicationContext();
        pm = context.getPackageManager();
        this.pinList = new LinkedHashSet<ApkSignaturePin>();
    }

    public static TrustedIntents get(Context context) {
        if (instance == null)
            instance = new TrustedIntents(context);
        return instance;
    }

    /**
     * Check whether a resolved {@link Activity} is trusted.
     *
     * @param resolveInfo the one to check
     * @return whether the {@code Intent}'s receiver is trusted
     */
    public boolean isReceiverTrusted(ResolveInfo resolveInfo) {
        return isPackageNameTrusted(resolveInfo.activityInfo.packageName);
    }

    /**
     * Creates an {@link Intent#ACTION_CHOOSER ACTION_CHOOSER} {@link Intent}
     * that puts trusted apps at the top of the list. Careful, it does not
     * filter out untrusted apps!
     *
     * @param target The {@link Intent} that the user will be selecting an
     *            activity to perform.
     * @param title Optional title that will be displayed in the chooser.
     * @return Return a new Intent object that you can hand to
     *         {@link Context#startActivity(Intent) Context.startActivity()} and
     *         related methods.
     */
    @SuppressLint("NewApi")
    public Intent createChooser(Intent target, CharSequence title) {
        Intent intent = new Intent(Intent.ACTION_CHOOSER);
        intent.putExtra(Intent.EXTRA_INTENT, target);
        if (title != null) {
            intent.putExtra(Intent.EXTRA_TITLE, title);
        }

        List<LabeledIntent> targetedIntents = new ArrayList<LabeledIntent>();
        List<ResolveInfo> resolvedActivities = pm.queryIntentActivities(target, 0);
        if (!resolvedActivities.isEmpty()) {
            for (ResolveInfo resolveInfo : resolvedActivities) {
                if (isReceiverTrusted(resolveInfo)) {
                    String packageName = resolveInfo.activityInfo.packageName;
                    LabeledIntent includedIntent = new LabeledIntent(target,
                            context.getPackageName(),
                            "(trusted)", android.R.drawable.star_big_on);
                    includedIntent.setPackage(packageName);
                    targetedIntents.add(includedIntent);
                }
            }
        }

        intent.putExtra(Intent.EXTRA_INITIAL_INTENTS,
                targetedIntents.toArray(new Parcelable[] {}));

        if (Build.VERSION.SDK_INT < 16)
            return intent; // the ClipData stuff was added in 4.1/android-16

        // Migrate any clip data and flags from target.
        int permFlags = target.getFlags()
                & (Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
        if (permFlags != 0) {
            ClipData targetClipData = target.getClipData();
            if (targetClipData == null && target.getData() != null) {
                ClipData.Item item = new ClipData.Item(target.getData());
                String[] mimeTypes;
                if (target.getType() != null) {
                    mimeTypes = new String[] {
                            target.getType()
                    };
                } else {
                    mimeTypes = new String[] {};
                }
                targetClipData = new ClipData(null, mimeTypes, item);
            }
            if (targetClipData != null) {
                intent.setClipData(targetClipData);
                intent.addFlags(permFlags);
            }
        }

        return intent;
    }

    public boolean isReceiverTrusted(String packageName) {
        try {
            checkTrustedSigner(packageName);
        } catch (NameNotFoundException e) {
            e.printStackTrace();
            return false;
        } catch (CertificateException e) {
            return false;
        }
        return true;
    }

    /**
     * Check whether a resolved {@link Activity} is trusted.
     *
     * @param activityInfo the one to check
     * @return whether the {@code Intent}'s receiver is trusted
     */
    public boolean isReceiverTrusted(ActivityInfo activityInfo) {
        return isPackageNameTrusted(activityInfo.packageName);
    }

    /**
     * Check an {@link Intent} is trusted based on the {@code packageName} set
     * by {@link Intent#setPackage(String)}
     *
     * @param intent the one to check
     * @return whether the {@code Intent}'s receiver is trusted
     */
    public boolean isReceiverTrusted(Intent intent) {
        if (!isIntentSane(intent))
            return false;
        String packageName = intent.getPackage();
        if (TextUtils.isEmpty(packageName)) {
            packageName = intent.getComponent().getPackageName();
        }
        return isPackageNameTrusted(packageName);
    }

    /**
     * Check whether a {@code packageName} is trusted.
     *
     * @param packageName the one to check
     * @return whether the {@code packageName} is trusted
     */
    public boolean isPackageNameTrusted(String packageName) {
        try {
            checkTrustedSigner(packageName);
        } catch (NameNotFoundException e) {
            e.printStackTrace();
            return false;
        } catch (CertificateException e) {
            return false;
        }
        return true;
    }

    public Intent getIntentFromTrustedSender(Activity activity)
            throws NameNotFoundException, CertificateException {
        Intent intent = activity.getIntent();
        if (!isIntentSane(intent))
            throw new NameNotFoundException(
                    "Intent incomplete or was sent using startActivity() instead of startActivityWithResult()");
        String packageName = intent.getPackage();
        if (TextUtils.isEmpty(packageName)) {
            packageName = intent.getComponent().getPackageName();
        }
        if (TextUtils.isEmpty(packageName))
            throw new NameNotFoundException(packageName);
        checkTrustedSigner(packageName);
        return intent;
    }

    private boolean isIntentSane(Intent intent) {
        if (intent == null)
            return false;
        if (TextUtils.isEmpty(intent.getPackage())) {
            ComponentName componentName = intent.getComponent();
            if (componentName == null || TextUtils.isEmpty(componentName.getPackageName())) {
                return false;
            }
        }
        return true;
    }

    /**
     * Add an APK signature that is always trusted for any packageName.
     *
     * @param cls {@link Class} of the {@link ApkSignaturePin} to trust
     * @return boolean
     * @throws {@link IllegalArgumentException} the class cannot be instantiated
     */
    public boolean addTrustedSigner(Class<? extends ApkSignaturePin> cls) {
        try {
            Constructor<? extends ApkSignaturePin> constructor = cls.getConstructor();
            return pinList.add((ApkSignaturePin) constructor.newInstance((Object[]) null));
        } catch (Exception e) {
            e.printStackTrace();
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Remove an APK signature from the trusted set.
     *
     * @param cls {@link Class} of the {@link ApkSignaturePin} to remove
     */
    public boolean removeTrustedSigner(Class<? extends ApkSignaturePin> cls) {
        for (ApkSignaturePin pin : pinList) {
            if (pin.getClass().equals(cls)) {
                return pinList.remove(pin);
            }
        }
        return false;
    }

    /**
     * Remove all {@link ApkSignaturePin}s from the trusted set.
     */
    public boolean removeAllTrustedSigners() {
        pinList.clear();
        return pinList.isEmpty();
    }

    /**
     * Check if a {@link ApkSignaturePin} is trusted.
     *
     * @param cls {@link Class} of the {@link ApkSignaturePin} to check
     */
    public boolean isTrustedSigner(Class<? extends ApkSignaturePin> cls) {
        for (ApkSignaturePin pin : pinList) {
            if (pin.getClass().equals(cls)) {
                return true;
            }
        }
        return false;
    }

    public void checkTrustedSigner(String packageName)
            throws NameNotFoundException, CertificateException {
        PackageInfo packageInfo = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
        checkTrustedSigner(packageInfo.signatures);
    }

    public void checkTrustedSigner(PackageInfo packageInfo)
            throws NameNotFoundException, CertificateException {
        checkTrustedSigner(packageInfo.signatures);
    }

    public void checkTrustedSigner(Signature[] signatures)
            throws NameNotFoundException, CertificateException {
        if (signatures == null || signatures.length == 0)
            throw new CertificateException("signatures cannot be null or empty!");
        for (int i = 0; i < signatures.length; i++)
            if (signatures[i] == null || signatures[i].toByteArray().length == 0)
                throw new CertificateException("Certificates cannot be null or empty!");

        // check whether the APK signer is trusted for all apps
        for (ApkSignaturePin pin : pinList)
            if (areSignaturesEqual(signatures, pin.getSignatures()))
                return; // found a matching trusted APK signer

        throw new CertificateException("APK signatures did not match!");
    }

    public boolean areSignaturesEqual(Signature[] sigs0, Signature[] sigs1) {
        // TODO where is Android's implementation of this that I can just call?
        if (sigs0 == null || sigs1 == null)
            return false;
        if (sigs0.length == 0 || sigs1.length == 0)
            return false;
        if (sigs0.length != sigs1.length)
            return false;
        for (int i = 0; i < sigs0.length; i++)
            if (!sigs0[i].equals(sigs1[i]))
                return false;
        return true;
    }

    public void startActivity(Context context, Intent intent) throws CertificateException {
        if (!isIntentSane(intent))
            throw new ActivityNotFoundException("The intent was null or empty!");
        String packageName = intent.getPackage();
        if (TextUtils.isEmpty(packageName)) {
            packageName = intent.getComponent().getPackageName();
            intent.setPackage(packageName);
        }
        try {
            checkTrustedSigner(packageName);
        } catch (NameNotFoundException e) {
            e.printStackTrace();
            throw new ActivityNotFoundException(e.getLocalizedMessage());
        }
        context.startActivity(intent);
    }
}
