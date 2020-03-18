package com.kodeholic.httpswithopenssl.common;

import android.app.ActivityManager;
import android.content.Context;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.os.AsyncTask;
import android.util.LruCache;
import android.view.View;
import android.view.animation.AlphaAnimation;
import android.widget.ImageView;

import com.jakewharton.disklrucache.DiskLruCache;
import com.kodeholic.httpswithopenssl.lib.http.HttpListener;
import com.kodeholic.httpswithopenssl.lib.http.HttpResponse;
import com.kodeholic.httpswithopenssl.lib.http.HttpUtil;
import com.kodeholic.httpswithopenssl.lib.util.Log;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;

public class BitmapCacheManager {
    public static final String TAG = BitmapCacheManager.class.getSimpleName();

    public static final int APP_VERSION = 1;
    public static final int VALUE_COUNT = 1;
    public static final int DISK_CACHE_SIZE = 150 * 1024 * 1024;

    private volatile static BitmapCacheManager sInstance;
    private Context mContext = null;

    //비트맵 디스크/메모리 캐시
    private DiskLruCache mDiskCache;
    private LruCache<String, Bitmap> mBitmapCache;

    public interface LoadedListener {
        public void onLoaded(boolean result, boolean asyncFlag, String text);
    }

    private BitmapCacheManager(Context context) {
        try {
            //메모리 기반의 비트맵 캐시 생성
            final int memClass = ((ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE)).getMemoryClass();
            final int memCacheSize = 1024 * 1024 * memClass / 8;
            Log.d(TAG, "create Memory Cache "
                    + "- memClass: " + memClass
                    + ", memCacheSize: " + memCacheSize
            );
            mBitmapCache = new LruCache<String, Bitmap>(memCacheSize) {
                @Override
                protected int sizeOf(String key, Bitmap value) {
                    return value.getByteCount();
                }
            };

            //디스크 기반의 비트맵 캐쉬 생성
            //File cacheDir = new File(PTTConfig.DIR_THUMBNAIL);
            File cacheDir = new File(getThumbnailDir(context));
            if (!cacheDir.exists()) {
                cacheDir.mkdirs();
            }
            Log.d(TAG, "create Memory Cache "
                    + "- cacheDir: " + cacheDir.getAbsolutePath()
                    + ", appVersion: " + APP_VERSION
                    + ", valueCount: " + VALUE_COUNT
                    + ", cacheSize: " + DISK_CACHE_SIZE
            );
            mDiskCache = DiskLruCache.open(cacheDir, APP_VERSION, VALUE_COUNT, DISK_CACHE_SIZE);
        }
        catch (IOException e) {
            e.printStackTrace();
        }

        mContext = context;
    }

    public static BitmapCacheManager getInstance(Context context) {
        if (sInstance == null) {
            synchronized (BitmapCacheManager.class) {
                if (sInstance == null) {
                    sInstance = new BitmapCacheManager(context);
                }
            }
        }
        return sInstance;
    }

    public void clear() {
        if (mBitmapCache != null) { mBitmapCache.evictAll(); }
    }

    private String toDiskCacheKey(String url) {
        try {
//            MessageDigest md5 = MessageDigest.getInstance("MD5");
//            return Utils.byte2String(md5.digest(url.getBytes()), true);

            return url.hashCode() + "";
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public boolean changeBitmapCache(String from, String to) {
        Log.d(TAG, "changeBitmapCacheKey() - from: " + from + ", to: " + to);
        if (from == null || to == null) {
            Log.d(TAG, "changeBitmapCacheKey() - failed! - from: " + from + ", to: " + to);
            return false;
        }

        Bitmap value = getFromBitmapCache(from, "changeBitmapCache");
        if (value != null) {
            putToBitmapCache(to, value, "changeBitmapCache");
            return true;
        }

        byte[] bytes = getFromDiskCache(toDiskCacheKey(from), "changeBitmapCache()");
        if (bytes != null) {
            putToDiskCache(toDiskCacheKey(to), bytes, "changeBitmapCache()");
            return true;
        }

        return false;
    }

    public void loadBitmap(String imgUrl, final ImageView imageView, String f) {
        Log.d(TAG, "loadBitmap() - f: " + f + ", imgUrl: " + imgUrl + ", imageView: " + imageView);
        try {
            //이미 Task가 실행 중이면서 imgUrl이 다를 경우, 중지시킨다.
            if (cancelPotentialBitmapWork(imgUrl, imageView)) {
                //로딩중을 보이게 하기 위해, GONE 처리
                imageView.setVisibility(View.INVISIBLE);

                //MemoryCache에서 hit되면 bitmap을 imageView에 바로 꼽고 리턴한다.
                Bitmap value = getFromBitmapCache(imgUrl, f);
                if (value != null) {
                    setImageBitmap(imageView, value, 0);
                    return;
                }

                //Task를 실행시킨다.
                final BitmapWorkerTask task = new BitmapWorkerTask(imageView);
                final AsyncDrawable asyncDrawable = new AsyncDrawable(mContext.getResources(), null, task);
                imageView.setImageDrawable(asyncDrawable);
                task.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, imgUrl);
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return;
    }

    /**
     * 해당 View를 대상으로 이미 작업이 전개중이면, 작업을 중지시킨다.
     *
     * @param url
     * @param imageView
     * @return
     */
    private boolean cancelPotentialBitmapWork(String url, ImageView imageView) {
        final BitmapWorkerTask bitmapWorkerTask = getBitmapWorkerTask(imageView);

        if (bitmapWorkerTask != null) {
            final String bitmapData = bitmapWorkerTask.url;
            if (!bitmapData.equals(url)) {
                //이전 작업을 취소한다.
                bitmapWorkerTask.cancel(true);

                //디스크 캐쉬 확인 후, 다운로드 시도한다.
                String diskCacheKey = toDiskCacheKey(url);
                if (!containsKeyAtDiskCache(diskCacheKey, "cancelPotentialBitmapWork")) {
                    putLazyDownloaderJob(url);
                }
            } else {
                //동일 작업을 실행한다.
                return false;
            }
        }
        // No task associated with the ImageView, or an existing task was cancelled
        return true;
    }

    private BitmapWorkerTask getBitmapWorkerTask(ImageView imageView) {
        if (imageView != null) {
            final Drawable drawable = imageView.getDrawable();
            if (drawable instanceof AsyncDrawable) {
                final AsyncDrawable asyncDrawable = (AsyncDrawable) drawable;
                return asyncDrawable.getBitmapWorkerTask();
            }
        }
        return null;
    }

    private Bitmap byte2Bitmap(String url, byte[] bytes) {
        try {
            Bitmap bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
            if (bitmap != null) {
                putToBitmapCache(url, bitmap, "byte2Bitmap");
                return bitmap;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        Log.d(TAG, "byte2Bitmap() - bitmap is null!");
        return null;
    }

    private Bitmap path2Bitmap(String path) {
        if (path.toLowerCase().startsWith("http")) {
            return url2Bitmap(path);
        }
        return file2Bitmap(path);
    }

    private Bitmap file2Bitmap(String path) {
        Log.d(TAG, "file2Bitmap() - path: " + path);
        File file = new File(path);
        if (!file.exists()) {
            Log.d(TAG, "file2Bitmap() - file(" + file.getAbsolutePath() + ") not exists!");
            return null;
        }

        InputStream fis = null;
        try {
            byte[] bytes = new byte[(int) file.length()];
            fis = new FileInputStream(file);
            fis.read(bytes);
            if (bytes.length > 0) {
                //DiskCache에 저장한다.
                putToDiskCache(toDiskCacheKey(path), bytes, "file2Bitmap");
                if (bytes == null) {
                    return null;
                }

                return byte2Bitmap(path, bytes);
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (Exception ignore) {
                    ;
                }
                fis = null;
            }
        }

        return null;
    }

    private Bitmap url2Bitmap(String url) {
        Log.d(TAG, "url2Bitmap() - url: " + url);
        try {
            //Http URI 및 헤더 정보 설정
            HttpUtil http = new HttpUtil(mContext);
            http.putPath(url);

            //Http 파라미터 설정
            final HttpUtil.Param param = http.getParam();
            param.setConnectTimeo(15 * 1000);
            param.setExecTimeo(15 * 1000);
            param.setMaxTries(1);
            param.setBaoStream(new ByteArrayOutputStream());
            param.setListener(0, new HttpListener() {
                @Override
                public void onProgress(int httpSequence, int current, int total) {
                    //Log.d(TAG, "url2Bitmap() - " + current + " / " + total);
                }

                @Override
                public void onResponse(int httpSequence, int httpReason, HttpResponse httpResponse) {
                }
            });

            //Http 서버에 요청한다.
            byte[] bytes = http.loadThumbnail();
            if (bytes != null) {
                //DiskCache에 저장한다.
                putToDiskCache(toDiskCacheKey(url), bytes, "url2Bitmap");

                return byte2Bitmap(url, bytes);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private void putToBitmapCache(String key, Bitmap value, String f) {
        try {
            if (mBitmapCache.get(key) == null) {
                mBitmapCache.put(key, value);
            }
            Log.v(TAG, "putToBitmapCache() - f: " + f
                    + ", key: " + key
                    + ", value.size: " + value.getByteCount() + ", row" + value.getRowBytes()
                    + ", size: " + mBitmapCache.size() + "/" + mBitmapCache.maxSize()
                    + ", hit: " + mBitmapCache.hitCount()
                    + ", miss: " + mBitmapCache.missCount()
            );
        } catch (Exception e) {
            e.printStackTrace();
        }

        return;
    }

    private Bitmap getFromBitmapCache(String key, String f) {
        try {
            Bitmap value = mBitmapCache.get(key);
            Log.v(TAG, "getFromBitmapCache() - f: " + f
                    + ", key: " + key
                    + ", value: " + value
                    + ", size: " + mBitmapCache.size() + "/" + mBitmapCache.maxSize()
                    + ", hit: " + mBitmapCache.hitCount()
                    + ", miss: " + mBitmapCache.missCount()
            );

            return value;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private void putToDiskCache(String key, byte[] bytes, String f) {
        Log.d(TAG, "putToDiskCache() - f: " + f + ", key: " + key + ", bytes: " + bytes);
        DiskLruCache.Editor editor = null;
        OutputStream out = null;
        try {
            if ((editor = mDiskCache.edit(key)) == null) {
                Log.d(TAG, "putToDiskCache() - f: " + f + ", key: " + key + " - fail to mDiskCache.edit()");
                return;
            }
            //스트림에 bytes 배열을 쓴다.
            out = new BufferedOutputStream(editor.newOutputStream(0), 8192);
            out.write(bytes);

            //flush and commit!
            mDiskCache.flush();
            editor.commit();

            Log.d(TAG, "putToDiskCache() - f: " + f + ", key: " + key + " - success!");
        }
        catch (Exception e) {
            Log.e(TAG, "putToDiskCache() - f: " + f + ", key: " + key + " - failed!");
            try {
                if (editor != null) {
                    editor.abort();
                }
            }
            catch (IOException ignored) {
            }
        }
        finally {
            try {
                if (out != null) {
                    out.close();
                }
            } catch (IOException ignore) {
            }
        }
    }

    private byte[] getFromDiskCache(String key, String f) {
        Log.d(TAG, "getFromDiskCache() - f: " + f + ", key: " + key);
        DiskLruCache.Snapshot snapshot = null;
        try {
            if ((snapshot = mDiskCache.get(key)) == null) {
                Log.d(TAG, "getFromDiskCache() - f: " + f + ", key: " + key + " - fail to mDiskCache.get()");
                return null;
            }
            final InputStream in = snapshot.getInputStream(0);
            if (in != null) {
                int length = in.available();
                byte[] bytes = new byte[length];
                in.read(bytes);

                Log.d(TAG, "getFromDiskCache() - f: " + f + ", key: " + key + " - success!");
                return bytes;
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        finally {
            if (snapshot != null) {
                snapshot.close();
            }
        }
        Log.e(TAG, "getFromDiskCache() - f: " + f + ", key: " + key + " - failed!");

        return null;
    }

    private boolean containsKeyAtDiskCache(String key, String f) {
        Log.d(TAG, "containsKeyAtDiskCache() - f: " + f + ", key: " + key);
        boolean contained = false;
        DiskLruCache.Snapshot snapshot = null;
        try {
            snapshot = mDiskCache.get(key);
            contained = (snapshot != null);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (snapshot != null) {
                snapshot.close();
            }
        }

        return contained;
    }


    /**
     * ...
     */
    public class AsyncDrawable extends BitmapDrawable {
        private final WeakReference<BitmapWorkerTask> bitmapWorkerTaskReference;

        public AsyncDrawable(Resources res, Bitmap bitmap, BitmapWorkerTask bitmapWorkerTask) {
            super(res, bitmap);
            bitmapWorkerTaskReference = new WeakReference<BitmapWorkerTask>(bitmapWorkerTask);
        }

        public BitmapWorkerTask getBitmapWorkerTask() {
            return bitmapWorkerTaskReference.get();
        }
    }

    /**
     * Bitmap을 ImageView에 적재하는 기능을 수행한다.
     */
    public class BitmapWorkerTask extends AsyncTask<Object, Void, Bitmap> {
        private final WeakReference<ImageView> weakReference;
        private String url = "";
        private String decryptFailMsg = "";

        public BitmapWorkerTask(ImageView imageView) {
            weakReference = new WeakReference<ImageView>(imageView);
        }

        @Override
        protected Bitmap doInBackground(Object... objects) {
            try {
                url = (String)objects[0];

                //DiskCache에서 조회
                String diskCacheKey = toDiskCacheKey(url);
                if (containsKeyAtDiskCache(diskCacheKey, "doInBackground")) {
                    byte[] bytes = getFromDiskCache(diskCacheKey, "doInBackground");
                    if (bytes == null) {
                        Log.e(TAG, "doInBackground() - bytes can't be NULL!");
                        return path2Bitmap(url);
                    }

                    //복호화된 bytes를 bitmap으로 변환한다.
                    Bitmap bitmap = byte2Bitmap(url, bytes);
                    if (bitmap == null) {
                        Log.e(TAG, "doInBackground() - bytes can't be NULL!");
                        return path2Bitmap(url);
                    }

                    return bitmap;
                }

                return path2Bitmap(url);
            }
            catch (Exception e) {
                e.printStackTrace();
            }

            return null;
        }

        @Override
        protected void onPostExecute(Bitmap bitmap) {
            if (isCancelled()) {
                bitmap = null;
            }

            if (weakReference != null && bitmap != null) {
                final ImageView imageView = weakReference.get();
                final BitmapWorkerTask bitmapWorkerTask = getBitmapWorkerTask(imageView);
                if (this == bitmapWorkerTask && imageView != null) {
                    setImageBitmap(imageView, bitmap, 300);
                }
            }
        }
    }

    private void setImageBitmap(ImageView view, Bitmap bitmap, long duration) {
        if (view != null) {
            if (duration >= 0) {
                fadeIn(view, 0, duration);
            }
            view.setVisibility(View.VISIBLE);
            view.setImageBitmap(bitmap);
        }
    }

    /////////////////////////////////////////////////////////////
    //
    /////////////////////////////////////////////////////////////
    private void fadeIn(View view, long delay, long duration) {
        AlphaAnimation alphaAnimation = new AlphaAnimation(0, 1);
        alphaAnimation.setStartOffset(delay);
        alphaAnimation.setDuration(duration);
        view.startAnimation(alphaAnimation);
    }

    ////////////////////////////////////////////////////////////////
    //
    // https://ringsterz.wordpress.com/2014/11/27/bitmap%EC%9D%84-ui-thread-%EC%99%B8%EB%B6%80%EC%97%90%EC%84%9C-%EC%B2%98%EB%A6%AC%ED%95%98%EA%B8%B0-1-%EC%9D%BC%EB%B0%98-view/
    // Bitmap을 UI Thread 외부에서 처리하기 (1) – 일반 View
    //
    ////////////////////////////////////////////////////////////////
//    class BitmapWorkerTask extends AsyncTask<Integer, Void, Bitmap> {
//        private final WeakReference<ImageView> imageViewReference;
//        private int data = 0;
//
//        public BitmapWorkerTask(ImageView imageView) {
//            // Use a WeakReference to ensure the ImageView can be garbage collected
//            imageViewReference = new WeakReference<ImageView>(imageView);
//        }
//
//        // Decode image in background.
//        @Override
//        protected Bitmap doInBackground(Integer... params) {
//            data = params[0];
//            return decodeSampledBitmapFromResource(mContext.getResources(), data, 100, 100);
//        }
//
//        // Once complete, see if ImageView is still around and set bitmap.
//        @Override
//        protected void onPostExecute(Bitmap bitmap) {
//            if (imageViewReference != null && bitmap != null) {
//                final ImageView imageView = imageViewReference.get();
//                if (imageView != null) {
//                    imageView.setImageBitmap(bitmap);
//                }
//            }
//        }
//    }
//
//    public void loadBitmap(int resId, ImageView imageView) {
//        BitmapWorkerTask task = new BitmapWorkerTask(imageView);
//        task.execute(resId);
//    }

    ////////////////////////////////////////////////////////////////
    //
    // https://ringsterz.wordpress.com/2014/11/27/bitmap%EC%9D%84-ui-thread-%EC%99%B8%EB%B6%80%EC%97%90%EC%84%9C-%EC%B2%98%EB%A6%AC%ED%95%98%EA%B8%B0-2-listview-gridview/
    // Bitmap을 UI Thread 외부에서 처리하기 (2) – ListView, GridView
    //
    ////////////////////////////////////////////////////////////////
//    static class AsyncDrawable extends BitmapDrawable {
//        private final WeakReference<BitmapWorkerTask> bitmapWorkerTaskReference;
//
//        public AsyncDrawable(Resources res, Bitmap bitmap, BitmapWorkerTask bitmapWorkerTask) {
//            super(res, bitmap);
//            bitmapWorkerTaskReference = new WeakReference<BitmapWorkerTask>(bitmapWorkerTask);
//        }
//
//        public BitmapWorkerTask getBitmapWorkerTask() {
//            return bitmapWorkerTaskReference.get();
//        }
//    }
//
//    public void loadBitmap(int resId, ImageView imageView) {
//        if (cancelPotentialWork(resId, imageView)) {
//            final BitmapWorkerTask task = new BitmapWorkerTask(imageView);
//            final AsyncDrawable asyncDrawable = new AsyncDrawable(getResources(), mPlaceHolderBitmap, task);
//            imageView.setImageDrawable(asyncDrawable); // imageView에 AsyncDrawable을 묶어줌
//            task.execute(resId);
//        }
//    }
//
//    public static boolean cancelPotentialWork(int data, ImageView imageView) {
//        final BitmapWorkerTask bitmapWorkerTask = getBitmapWorkerTask(imageView);
//
//        if (bitmapWorkerTask != null) {
//            final int bitmapData = bitmapWorkerTask.data;
//            // If bitmapData is not yet set or it differs from the new data
//            if (bitmapData == 0 || bitmapData != data) {
//                // Cancel previous task
//                bitmapWorkerTask.cancel(true);
//            } else {
//                // The same work is already in progress
//                return false;
//            }
//        }
//        // No task associated with the ImageView, or an existing task was cancelled
//        return true;
//    }
//
//    private static BitmapWorkerTask getBitmapWorkerTask(ImageView imageView) {
//        if (imageView != null) {
//            final Drawable drawable = imageView.getDrawable();
//            if (drawable instanceof AsyncDrawable) { //drawable 이 null일 경우 false 반환
//                final AsyncDrawable asyncDrawable = (AsyncDrawable) drawable;
//                return asyncDrawable.getBitmapWorkerTask();
//            }
//        }
//        return null;
//    }
//
//    class BitmapWorkerTask extends AsyncTask<Integer, Void, Bitmap> {
//
//        @Override
//        protected void onPostExecute(Bitmap bitmap) {
//            if (isCancelled()) {
//                bitmap = null;
//            }
//
//            if (imageViewReference != null && bitmap != null) {
//                final ImageView imageView = imageViewReference.get();
//                final BitmapWorkerTask bitmapWorkerTask =
//                        getBitmapWorkerTask(imageView);
//                if (this == bitmapWorkerTask && imageView != null) {
//                    imageView.setImageBitmap(bitmap);
//                }
//            }
//        }
//    }
    ////////////////////////////////////////////////////////////////
    //
    // https://ringsterz.wordpress.com/2014/11/27/imageview%EC%97%90-%EB%8C%80%EC%9A%A9%EB%9F%89-bitmap-%ED%9A%A8%EA%B3%BC%EC%A0%81%EC%9C%BC%EB%A1%9C-%EB%A1%9C%EB%94%A9%ED%95%98%EA%B8%B0/
    // ImageView에 대용량 Bitmap 효과적으로 로딩하기
    //
    ////////////////////////////////////////////////////////////////
//    public static int calculateInSampleSize(BitmapFactory.Options options, int reqWidth, int reqHeight) {
//        // Raw height and width of image
//        final int height = options.outHeight;
//        final int width = options.outWidth;
//        int inSampleSize = 1;
//
//        if (height > reqHeight || width > reqWidth) {
//            final int halfHeight = height / 2;
//            final int halfWidth = width / 2;
//
//            // Calculate the largest inSampleSize value that is a power of 2 and keeps both
//            // height and width larger than the requested height and width.
//            while ((halfHeight / inSampleSize) > reqHeight && (halfWidth / inSampleSize) > reqWidth) {
//                inSampleSize *= 2;
//            }
//        }
//
//        return inSampleSize;
//    }
//
//    public static Bitmap decodeSampledBitmapFromResource(Resources res, int resId, int reqWidth, int reqHeight) {
//        // First decode with inJustDecodeBounds=true to check dimensions
//        final BitmapFactory.Options options = new BitmapFactory.Options();
//        options.inJustDecodeBounds = true;
//        BitmapFactory.decodeResource(res, resId, options);
//
//        // Calculate inSampleSize
//        options.inSampleSize = calculateInSampleSize(options, reqWidth, reqHeight);
//
//        // Decode bitmap with inSampleSize set
//        options.inJustDecodeBounds = false;
//        return BitmapFactory.decodeResource(res, resId, options);
//    }
//
//    public static void sample() {
//        //mImageView.setImageBitmap(decodeSampledBitmapFromResource(getResources(), R.id.myimage, 100, 100));
//    }


    /////////////////////////////////////////////////////////////////////////
    //
    // LazyDownloader
    //
    /////////////////////////////////////////////////////////////////////////
    private static final int MAX_LAZYDOWNLOADER_NUM = 10;
    //Async downloader
    private boolean mLazyDownloaderTaskRunning = false;
    private List<LazyDownloaderJob> mLDPendingQueue;
    private List<LazyDownloaderJob> mLDProcessQueue;
    private LazyDownloaderTask      mLazyDownloaderTask;
    private int mLazyDownloaderSequence = 0;

    public class LazyDownloaderJob {
        public String     imgUrl;
        public LazyDownloaderJob(String imgUrl) {
            this.imgUrl = imgUrl;
        }
    }

    public class LazyDownloaderTask extends Thread {
        public LazyDownloaderTask() {
            super("LazyDownloaderTask");
        }

        @Override
        public void run() {
            Log.d(TAG, "LazyDownloaderTask STARTED.");

            while (mLazyDownloaderTaskRunning) {
                try {
                    LazyDownloaderJob job = getLazyDownloaderJob(5 * 60 * 1000);
                    if (job != null) {
                        mLazyDownloaderSequence += 1;

                        //실제 다운로드 쓰레드를 생성/실행한다.
                        Thread runner = new Thread(new LazyDownloader(mLazyDownloaderSequence, job));
                        runner.start();
                    }
                    Log.d(TAG, "LazyDownloaderTask() "
                            + "- PendingQ.size: " + mLDPendingQueue.size()
                            + ", ProcessQ.size: " + mLDProcessQueue.size());
                }
                catch (Exception e) {
                    e.printStackTrace();
                }
            }

            Log.d(TAG, "LazyDownloaderTask STOPPED.");
        }
    }

    public void startLazyDownloaderTask() {
        Log.d(TAG, "startLazyDownloaderTask()");
        mLDPendingQueue = new ArrayList<>();
        mLDProcessQueue = new ArrayList<>();
        mLazyDownloaderTaskRunning = true;
        mLazyDownloaderTask = new LazyDownloaderTask();
        mLazyDownloaderTask.start();
    }

    public void stopLazyDownloaderTask() {
        Log.d(TAG, "stopLazyDownloaderTask()");
        mLazyDownloaderTaskRunning = false;
        synchronized (mLDPendingQueue) {
            mLDPendingQueue.notifyAll();
        }
    }

    public void putLazyDownloaderJob(String imgUrl) {
        Log.d(TAG, "putLazyDownloaderJob() - imgUrl: " + imgUrl);
        synchronized (mLDPendingQueue) {
            if ((mLDPendingQueue.size() + mLDProcessQueue.size()) > MAX_LAZYDOWNLOADER_NUM) {
                Log.d(TAG, "putLazyDownloaderJob() - Too many jobs! size: "
                        + (mLDPendingQueue.size() + mLDProcessQueue.size()));
                return;
            }
            mLDPendingQueue.add(new LazyDownloaderJob(imgUrl));
            mLDPendingQueue.notifyAll();
        }

        return ;
    }

    /**
     * flow를 가지고 온다.
     * @param millis
     * @return
     */
    public LazyDownloaderJob getLazyDownloaderJob(long millis) {
        synchronized (mLDPendingQueue) {
            //size가 0인 경우, 대기한다.
            if (mLDPendingQueue.size() == 0) {
                try {
                    mLDPendingQueue.wait(millis);
                }
                catch (Exception ignore) {
                }
            }

            //size가 0보다 큰 경우, Job을 dequeue한다.
            if (mLDPendingQueue.size() > 0) {
                LazyDownloaderJob job = mLDPendingQueue.remove(0);
                mLDProcessQueue.add(job);
                mLDPendingQueue.notifyAll();
                return job;
            }
        }

        return null;
    }

    /**
     * Lazy 다운로더
     */
    public class LazyDownloader implements Runnable {
        private int sequence;

        //복호화 관련 키
        private LazyDownloaderJob job;

        public LazyDownloader(int sequence, LazyDownloaderJob job) {
            this.sequence = sequence;
            this.job      = job;
        }

        @Override
        public void run() {
            Log.d(TAG, "LazyDownloader[" + sequence + "] STARTED - " + job.imgUrl);
            try {
                String diskCacheKey = toDiskCacheKey(job.imgUrl);
                if (!containsKeyAtDiskCache(diskCacheKey, "loadLazyDownloader")) {
                    path2Bitmap(job.imgUrl);
                }
            }
            catch (Exception e) {
                e.printStackTrace();
            }
            Log.d(TAG, "LazyDownloader[" + sequence + "] STOPPED - " + job.imgUrl);

            synchronized (mLDPendingQueue) {
                mLDProcessQueue.remove(job);
                mLDPendingQueue.notifyAll();
            }
        }
    }

    /**
     * Thumbnail 경로를
     * @param context
     * @return
     */
    public static String getThumbnailDir(Context context) {
        return context.getFilesDir().getAbsolutePath() + "/thumbnail";
    }
}
