public class FileMetaData {
    private String fileName;
    private long fileSize;
    private String fileType;
    private String md5Hash;

    public FileMetaData(String fileName, long fileSize, String fileType, String md5Hash) {
        this.fileName = fileName;
        this.fileSize = fileSize;
        this.fileType = fileType;
        this.md5Hash = md5Hash;
    }

    public String getFileName() {
        return fileName;
    }

    public long getFileSize() {
        return fileSize;
    }

    public String getFileType() {
        return fileType;
    }

    public String getMd5Hash() {
        return md5Hash;
    }

    @Override
    public String toString() {
        return String.format("FileName: %s, Size: %dKB, Type: %s, MD5: %s",
                fileName, fileSize / 1024, fileType, md5Hash);
    }
}
