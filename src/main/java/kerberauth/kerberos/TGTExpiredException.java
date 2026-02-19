package kerberauth.kerberos;

public class TGTExpiredException extends Exception {
    public TGTExpiredException(String message) {
        super(message);
    }
}