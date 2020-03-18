package com.kodeholic.httpswithopenssl;

import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import com.kodeholic.httpswithopenssl.common.BitmapCacheManager;
import com.kodeholic.httpswithopenssl.common.BookManager;
import com.kodeholic.httpswithopenssl.common.PopupManager;
import com.kodeholic.httpswithopenssl.common.data.Book;
import com.kodeholic.httpswithopenssl.common.data.BookListRes;
import com.kodeholic.httpswithopenssl.lib.http.HttpResponse;
import com.kodeholic.httpswithopenssl.lib.util.Log;

public class MainActivity extends AppCompatActivity {
    public static final String TAG = MainActivity.class.getSimpleName();

    private Context mContext;
    private NewListAdapter mAdapter;
    private RecyclerView mListView;
    private SwipeRefreshLayout mPullToRefresh;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mContext = this;

        //adapter
        mAdapter = new NewListAdapter(new Book[0]);

        //list..
        mListView = findViewById(R.id.ll_list);
        mListView.setHasFixedSize(true);
        mListView.setAdapter(mAdapter);

        mPullToRefresh = findViewById(R.id.ll_refresh);
        mPullToRefresh.setOnRefreshListener(mRefreshListener);
        mPullToRefresh.setColorSchemeResources(R.color.colorPrimary,
                android.R.color.holo_green_dark,
                android.R.color.holo_orange_dark,
                android.R.color.holo_blue_dark);
    }

    private void updateView(final Book[] books, String f) {
        Log.d(TAG, "updateView() - f: " + f);
        mListView.post(new Runnable() {
            @Override
            public void run() {
                mAdapter.setData(books);
                mAdapter.notifyDataSetChanged();
            }
        });
    }

    private SwipeRefreshLayout.OnRefreshListener mRefreshListener = new SwipeRefreshLayout.OnRefreshListener() {
        @Override
        public void onRefresh() {

            BookManager.getInstance(mContext).newList(new BookManager.Listener() {
                @Override
                public void onResponse(HttpResponse response) {
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            mPullToRefresh.setRefreshing(false);
                        }
                    });

                    if (response.isSUCC()) {
                        BookListRes jsonRes = (BookListRes) response.getObject();
                        if (jsonRes != null || jsonRes.getError() != 0) {
                            updateView(jsonRes.getBookList().toArray(new Book[0]), "onResponse");
                        }
                    }
                }
            }, "onRefresh()");
        }
    };

    public class NewListAdapter extends RecyclerView.Adapter<BookItemViewHolder> {
        private Book[] data;
        private boolean detailStarting = false;

        public NewListAdapter(Book[] data) {
            this.data = data;
        }

        public void setData(Book[] data) {
            this.data = data;
        }

        @Override
        public BookItemViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View itemView = LayoutInflater.from(parent.getContext()).inflate(R.layout.list_item_book, parent, false);
            return new BookItemViewHolder(itemView);
        }

        @Override
        public void onBindViewHolder(final BookItemViewHolder holder, final int position) {
            final Book item = data[position];
            holder.tv_title.setText(item.getTitle());
            holder.tv_subtitle.setText(item.getSubTitle());
            holder.tv_isbn13.setText("(" + item.getIsbn13() + ")");
            holder.tv_price.setText(item.getPrice());
            //이미지를 view에 붙인다.
            BitmapCacheManager.getInstance(mContext).loadBitmap(
                    item.getImage(),
                    holder.iv_image,
                    TAG);
        }

        @Override
        public int getItemCount() {
            return data.length;
        }
    }

    public class BookItemViewHolder extends RecyclerView.ViewHolder {
        public ImageView iv_image;
        public TextView tv_title;
        public TextView  tv_subtitle;
        public TextView  tv_isbn13;
        public TextView  tv_price;
        public View      ll_link;
        public View      rowView;

        public BookItemViewHolder(View itemView) {
            super(itemView);

            rowView     = itemView;
            iv_image    = itemView.findViewById(R.id.iv_image);
            tv_title    = itemView.findViewById(R.id.tv_title);
            tv_subtitle = itemView.findViewById(R.id.tv_subtitle);
            tv_isbn13   = itemView.findViewById(R.id.tv_isbn13);
            tv_price    = itemView.findViewById(R.id.tv_price);
            ll_link     = itemView.findViewById(R.id.ll_link);
        }
    }
}
