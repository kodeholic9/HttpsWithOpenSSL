package com.kodeholic.httpswithopenssl.common.data;


public class SearchResult {
    private String queryString;
    private int    pageNo;
    private String jsonResult; //json format
    private long   searchTime;

    public SearchResult() {}
    public SearchResult(String queryString, int pageNo, String jsonResult) {
        this.queryString= queryString;
        this.pageNo     = pageNo;
        this.jsonResult = jsonResult;
        this.searchTime = System.currentTimeMillis();
    }

    public int length() {
        int ln = ((jsonResult != null) ? jsonResult.length() : 0);
        return ln;
    }

    public String getQueryString() {
        return queryString;
    }

    public void setQueryString(String queryString) {
        this.queryString = queryString;
    }

    public int getPageNo() {
        return pageNo;
    }

    public void setPageNo(int pageNo) {
        this.pageNo = pageNo;
    }

    public String getJsonResult() {
        return jsonResult;
    }

    public void setJsonResult(String jsonResult) {
        this.jsonResult = jsonResult;
    }

    public long getSearchTime() {
        return searchTime;
    }

    public void setSearchTime(long searchTime) {
        this.searchTime = searchTime;
    }

    @Override
    public String toString() {
        return "SearchResult{" +
                "queryString='" + queryString + '\'' +
                ", pageNo=" + pageNo +
                ", jsonResult='" + jsonResult + '\'' +
                ", searchTime=" + searchTime +
                '}';
    }
}
