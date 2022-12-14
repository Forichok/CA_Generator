package ru.mail;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Scanner;

public class App {
  public static void main(String[] args) {

    Scanner in = new Scanner(System.in);
    String path = null;
    Integer yearsLifetime = null;
    X500Name rootCertIssuer = null;
    String buff;
    String filePass;
    String keyStorePass;
    while (path == null) {
      System.out.println("Enter keystore file path to save:");
      buff = in.nextLine();

      if (new File(buff).exists()) {
        System.out.printf("File with path %s already exists. Try again:\n", buff);
        continue;
      }
      path = buff;
    }

    while (rootCertIssuer == null) {
      System.out.println("Enter certificate directory name:");

      buff = in.nextLine();

      if (buff == null || buff.length() == 0) {
        System.out.printf("Incorrect directory name %s", buff);
        continue;
      }

      try {
        rootCertIssuer = new X500Name(buff);
      } catch (Exception e) {
        System.out.println("Incorrect Dir Name");
      }

    }

    while (yearsLifetime == null) {
      System.out.println("Enter certificate lifetime in years:");
      try {
        yearsLifetime = in.nextInt();
      } catch (Exception e) {
        System.out.println("Incorrect input");
      }
    }

    System.out.println("Enter keystore password:");
    keyStorePass = in.next();

    System.out.println("Enter p12 file password:");
    filePass = in.next();

    try {
      KeyStore keyStore = generateRootCertificateKeyStore(keyStorePass, rootCertIssuer, yearsLifetime);
      saveKeystoreToFile(path, keyStore, filePass);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private static KeyStore generateRootCertificateKeyStore(String keystorePassword, X500Name rootCertIssuer, int yearsLifetime)
      throws OperatorCreationException, IOException, NoSuchAlgorithmException, CertificateException,
      NoSuchProviderException, InvalidAlgorithmParameterException, KeyStoreException {
    Security.addProvider(new BouncyCastleProvider());

//    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");
//    keyPairGenerator.initialize(new ECGenParameterSpec("Tc26-Gost-3410-12-256-paramSetA"));

    KeyPairGenerator keyPairGenerator =
        KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
    keyPairGenerator.initialize(2048);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    X509Certificate rootCert = getX509Certificate(rootCertIssuer, yearsLifetime, keyPair);

    KeyStore keystore = KeyStore.getInstance("PKCS12");
    keystore.load(null, null); // initialize new keystore

    keystore.setEntry(
        "root",
        new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), new X509Certificate[]{rootCert}),
        new KeyStore.PasswordProtection(keystorePassword.toCharArray()));
    return keystore;
  }


  private static X509Certificate getX509Certificate(X500Name rootCertIssuer, int yearsLifetime, KeyPair keyPair) throws OperatorCreationException, NoSuchAlgorithmException, CertIOException, CertificateException {
    Calendar calendar = Calendar.getInstance();
    calendar.add(Calendar.DATE, -1);
    Date startDate = calendar.getTime();

    calendar.add(Calendar.YEAR, yearsLifetime);
    Date endDate = calendar.getTime();

    BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

    ContentSigner rootCertContentSigner =
        new JcaContentSignerBuilder("SHA256WithRSA")
            .build(keyPair.getPrivate());
    X509v3CertificateBuilder rootCertBuilder =
        new JcaX509v3CertificateBuilder(
            rootCertIssuer,
            rootSerialNum,
            startDate,
            endDate,
            rootCertIssuer, // self-signed
            keyPair.getPublic());

    JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
    rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    rootCertBuilder.addExtension(
        Extension.subjectKeyIdentifier,
        false,
        rootCertExtUtils.createSubjectKeyIdentifier(keyPair.getPublic()));

    X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
    return new JcaX509CertificateConverter().getCertificate(rootCertHolder);
  }

  private static void saveKeystoreToFile(String path, KeyStore keyStore, String filePassword) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
    try (FileOutputStream os = new FileOutputStream(path)) {
      keyStore.store(os, filePassword.toCharArray());
    }
  }

}
