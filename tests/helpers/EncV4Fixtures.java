// Independent compatibility fixtures using the official SSE Java engine.
// Run against ssefenc.jar; production SunPack never loads Java or this helper.
import java.nio.file.*;
import java.io.*;
import java.util.*;
import java.util.zip.*;
import java.lang.reflect.*;
import com.paranoiaworks.sse.*;
import sse.org.bouncycastle.crypto.digests.Blake3Digest;
import sse.org.bouncycastle.crypto.params.Blake3Parameters;

public final class EncV4Fixtures {
    static byte[] zip(byte[] data) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(out)) {
            ZipEntry e = new ZipEntry("inside.txt"); e.setTime(0); z.putNextEntry(e); z.write(data); z.closeEntry();
        }
        return out.toByteArray();
    }
    @SuppressWarnings("unchecked")
    static byte[] enc(byte[] payload, int code, byte params, String password) throws Exception {
        int[] keySizes = {32,32,32,32,32,32,56,128,64,256};
        int[] nonceSizes = {16,16,16,8,16,8,8,128,32,192};
        Encryptor e = new Encryptor(password.toCharArray(), code, Encryptor.PURPOSE_FILE_ENCRYPTION, true);
        Method derive = Encryptor.class.getDeclaredMethod("deriveParamsArgon2id", byte[].class, Byte.class, int.class, int.class, Integer.class, Integer.class, Integer.class);
        derive.setAccessible(true);
        byte[] salt = new byte[32]; Arrays.fill(salt, (byte) 0x73);
        List<byte[]> keys = (List<byte[]>) derive.invoke(e, salt, params, keySizes[code], nonceSizes[code], 32, Encryptor.PURPOSE_FILE_ENCRYPTION, 3);
        byte[] key = keys.get(0), nonce = keys.get(1), auth = keys.get(2);
        byte[] header = {'S','S','E','F','E',4,(byte) code,params};
        int plaintextLength = 32 + payload.length;
        byte[] encrypted = new byte[((plaintextLength+127)/128)*128];
        Arrays.fill(encrypted, 0, 32, (byte) 'a'); System.arraycopy(payload, 0, encrypted, 32, payload.length);
        EncryptorPI cipher = new EncryptorPI(1);
        if (code != 9) cipher.encryptByteArrayCTR(nonce, key, encrypted, code);
        else {
            int k=0, n=0;
            int[] codes={7,2,0,8}, ks={128,32,32,64}, ns={128,16,16,32};
            for (int i=0;i<4;i++) {
                cipher.encryptByteArrayCTR(Arrays.copyOfRange(nonce,n,n+ns[i]), Arrays.copyOfRange(key,k,k+ks[i]), encrypted, codes[i]);
                k+=ks[i]; n+=ns[i];
            }
        }
        cipher.shutDownThreadExecutor();
        encrypted = Arrays.copyOf(encrypted, plaintextLength);
        Blake3Digest mac = new Blake3Digest(); mac.init(Blake3Parameters.key(auth));
        for (byte[] b : new byte[][]{nonce,header,salt,encrypted}) mac.update(b,0,b.length);
        byte[] tag = new byte[32]; mac.doFinal(tag,0);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] b : new byte[][]{header,salt,encrypted,tag}) out.write(b);
        e.wipeMasterKeys(); return out.toByteArray();
    }
    public static void main(String[] args) throws Exception {
        Path root = Paths.get(args[0]); Files.createDirectories(root);
        byte[] zip = zip("SunPack official ENC v4 compatibility\n".getBytes("UTF-8"));
        Files.write(root.resolve("expected.zip"), zip);
        for (int code=0;code<10;code++) Files.write(root.resolve("algorithm_"+code+".mov"), enc(zip,code,(byte)0,"sunpack-test"));
        Files.write(root.resolve("unicode.enc"), enc(zip,0,(byte)0,"contraseña中文😀"));
        Files.write(root.resolve("params_01.enc"), enc(zip,0,(byte)1,"sunpack-test"));
        Files.write(root.resolve("params_10.enc"), enc(zip,0,(byte)16,"sunpack-test"));
        byte[] corrupt = enc(zip,0,(byte)0,"sunpack-test"); corrupt[corrupt.length-1]^=1;
        Files.write(root.resolve("bad_mac.enc"),corrupt);
        corrupt = enc(zip,0,(byte)0,"sunpack-test"); corrupt[80]^=1;
        Files.write(root.resolve("bad_payload.enc"),corrupt);
        Files.write(root.resolve("truncated.enc"), Arrays.copyOf(corrupt,80));
        byte[] nested = enc(zip,4,(byte)0,"sunpack-test");
        ByteArrayOutputStream outer = new ByteArrayOutputStream();
        try(ZipOutputStream z = new ZipOutputStream(outer)) { z.putNextEntry(new ZipEntry("movie.bin")); z.write(nested); z.closeEntry(); }
        Files.write(root.resolve("nested.enc"), enc(outer.toByteArray(),0,(byte)0,"sunpack-test"));
        // Large authenticated ordinary bytes: the ENC reader must know nothing about ZIP.
        int largeCode = args.length > 1 ? Integer.parseInt(args[1]) : 0;
        int largeMiB = args.length > 2 ? Integer.parseInt(args[2]) : 32;
        byte[] large = new byte[largeMiB*1024*1024]; new Random(42).nextBytes(large);
        Files.write(root.resolve("large.enc"),enc(large,largeCode,(byte)0,"sunpack-test"));
        Files.write(root.resolve("large.expected"),large);
        byte[] invalid = new byte[512]; System.arraycopy(new byte[]{'S','S','E','F','E',4,99,0},0,invalid,0,8);
        Files.write(root.resolve("invalid_algorithm.enc"),invalid);
    }
}
