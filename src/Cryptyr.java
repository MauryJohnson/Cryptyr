import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
import java.util.Random;

import java.io.*;
import java.security.*;
import java.security.spec.*;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Base64;
import java.util.ArrayList;
import java.util.Arrays;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class Cryptyr {
	
	
	/**
	 * 
	 * @author MJ
	 *
	 *	Tuple contains two Objects
	 *
	 */
	public class Tuple<T,V> {
		
		public T First;
		public V Second;
		
		public Tuple(T t,V v) {
			this.First=t;
			this.Second = v;
		}
		
	}

	
	public class CIPHER{
		
		/**
		 * 
		 * 
		 * 
		 * @return
		 */
		public Cipher CreateCipher(SecretKey skey, IvParameterSpec iv,String FileIn,String FileOut) {
			Cipher ci = null;
			try {
				ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
			} catch (NoSuchAlgorithmException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (NoSuchPaddingException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			
			try {
				ci.init(Cipher.ENCRYPT_MODE, skey, iv);
			} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			EncryptCipher(ci,FileIn,FileOut);
			
			return ci;
		}
		
		
		public String DecryptCipher(Cipher ci, String FileName) {
			byte[] encoded = null;
			String plainText = null;
			try {
				encoded = Files.readAllBytes(Paths.get(FileName));
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			try {
				plainText = new String(ci.doFinal(encoded), "UTF-8");
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			return plainText;
			
		}
		
		public void EncryptCipher(Cipher ci, String FileInfo,String FileName) {
			try (FileOutputStream out = new FileOutputStream(FileName)) {
			    byte[] input = null;
				try {
					input = FileInfo.getBytes("UTF-8");
				} catch (UnsupportedEncodingException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			    byte[] encoded = ci.doFinal(input);
			    try {
					out.write(encoded);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} catch (IllegalBlockSizeException | BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (FileNotFoundException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			} catch (IOException e2) {
				// T ODO Auto-generated catch block
				e2.printStackTrace();
			}
		}
	}
	
	public class KEY extends Cryptyr{
		
		public IvParameterSpec ivspec = null;
		//public IvParameterSpec AESivspec = null;
		
		public  PublicKey GetPublicKey(String filename)
			    throws Exception {
			    
			    File f = new File(filename);
			    FileInputStream fis = new FileInputStream(f);
			    DataInputStream dis = new DataInputStream(fis);
			    byte[] keyBytes = new byte[(int)f.length()];
			    dis.readFully(keyBytes);
			    dis.close();

			    X509EncodedKeySpec spec =
			      new X509EncodedKeySpec(keyBytes);
			    KeyFactory kf = KeyFactory.getInstance("RSA");
			    return kf.generatePublic(spec);
			  }
		
		public SecretKey GenerateAESKey() {
			KeyGenerator kgen = null;
			try {
				kgen = KeyGenerator.getInstance("AES");
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			kgen.init(128);
			SecretKey skey = kgen.generateKey();
			
			this.ivspec = this.GenerateAESIv();
			
			return skey;
		}
		
		public void AESKeyDecrypt(SecretKey skey, String in,String out) {
			try {
			Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
			ci.init(Cipher.DECRYPT_MODE, skey, ivspec);
			//try (FileOutputStream out = new FileOutputStream(inputFile+".ver")){
			    new FILE().ProcessFile(ci, in, out);
			//}
			}catch(Exception e) {
				e.printStackTrace();
			}
		}
		
		public SecretKey GetAESKey(PublicKey pub, String inputFile) {
			
			SecretKey skey = null;
			IvParameterSpec ivspec = null;
			
			try{FileInputStream in = new FileInputStream(inputFile);
			
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, pub);
			byte[] b = new byte[256];
			in.read(b);
			byte[] keyb = cipher.doFinal(b);
			skey = new SecretKeySpec(keyb, "AES");
			
			byte[] iv = new byte[128/8];
			in.read(iv);
			ivspec = new IvParameterSpec(iv);
			
			}
			catch(Exception e) {
				e.printStackTrace();
			}
			
			this.ivspec = ivspec;
			
			return skey;
		}
		
		public void SaveAESKey(SecretKey skey, PrivateKey pvt ,String inputFile) {
			
			if(this.ivspec==null) {
				System.err.println("Cannot SAVE AES Key!!! NO AESivspec!!!!");
				return;
			}
			
			FileOutputStream out = null;
			try {
				out = new FileOutputStream(inputFile + ".enc");
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			Cipher cipher = null;
			try {
				cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			try {
				cipher.init(Cipher.ENCRYPT_MODE, pvt);
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			byte[] b = null;
			try {
				b = cipher.doFinal(skey.getEncoded());
			} catch (IllegalBlockSizeException | BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			try {
				
				out.write(b);
				
				out.write(this.ivspec.getIV());
		
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
			
			
		}
		
		public IvParameterSpec GenerateAESIv() {
			byte[] iv = new byte[128/8];
			new Random().nextBytes(iv);
			IvParameterSpec i = new IvParameterSpec(iv);
			
			this.ivspec = i;
			
			return i;
		}
		
		public void AESKeyEncrypt(SecretKey skey, String in,String out) {
			
			if(this.ivspec==null) {
				System.err.println("No AESivspec to Encrypt with!! ERROR");
				return;
			}
			
			Cipher ci = null;
			try {
				ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			try {
				ci.init(Cipher.ENCRYPT_MODE, skey, this.ivspec);
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			//try (FileInputStream in = new FileInputStream(inputFile)) {
			    try {
					new FILE().ProcessFile(ci, in, out);
				} catch (IllegalBlockSizeException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (BadPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			
		}
		
		public  SecretKey GetSecretKey(String FileName) {
			Object[] keyb = null;
			try {
				//keyb = Files.readAllBytes(Paths.get(FileName));
				
				keyb = (Object[])this.ProcessAfterBytes(new File(FileName),16);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			byte[] kb = new byte[keyb.length];
			int k=0;
			for(Object i: keyb) {
				kb[k] = (byte)i;
				k+=1;
			}
			return new SecretKeySpec(kb, "AES");
		}
		
		public Tuple<PublicKey,PrivateKey> GeneratePubPrivKeyPair() {
			KeyPairGenerator kpg = null;
			try {
				kpg = KeyPairGenerator.getInstance("RSA");
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			kpg.initialize(2048);
			KeyPair kp = kpg.generateKeyPair();	
			
			return new Tuple<PublicKey,PrivateKey>(kp.getPublic(),kp.getPrivate());
		
		}
		
		public PrivateKey GetPrivateKey(String filename)
			    throws Exception {
			    
			    File f = new File(filename);
			    FileInputStream fis = new FileInputStream(f);
			    DataInputStream dis = new DataInputStream(fis);
			    byte[] keyBytes = new byte[(int)f.length()];
			    dis.readFully(keyBytes);
			    dis.close();

			    PKCS8EncodedKeySpec spec =
			      new PKCS8EncodedKeySpec(keyBytes);
			    KeyFactory kf = KeyFactory.getInstance("RSA");
			    return kf.generatePrivate(spec);
			  }
		
		public void PublicKeyDecrypt(PublicKey pub,String encFile, String verFile) {
			Cipher cipher = null;
			try {
				cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			} catch (NoSuchAlgorithmException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			} catch (NoSuchPaddingException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			}
			try {
				cipher.init(Cipher.DECRYPT_MODE, pub);
			} catch (InvalidKeyException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			//try (FileInputStream in = new FileInputStream(encFile);
			  //   FileOutputStream out = new FileOutputStream(verFile)) {
			    try {
					this.new FILE().ProcessFile(cipher, encFile, verFile);
				} catch (IllegalBlockSizeException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (BadPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			//}
		}
		
		public void PrivateKeyDecrypt(PrivateKey pK,String encFile, String verFile) {
			Cipher cipher = null;
			try {
				cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			} catch (NoSuchAlgorithmException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			} catch (NoSuchPaddingException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			}
			try {
				cipher.init(Cipher.DECRYPT_MODE, pK);
			} catch (InvalidKeyException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			//try (FileInputStream in = new FileInputStream(encFile);
			  //   FileOutputStream out = new FileOutputStream(verFile)) {
			    try {
					this.new FILE().ProcessFile(cipher, encFile, verFile);
				} catch (IllegalBlockSizeException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (BadPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			//}
		}
		
		public void PublicKeyEncrypt(PublicKey pub, String inFile, String encFile) {
			Cipher ci = null;
			try {
				ci = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			try {
				ci.init(Cipher.ENCRYPT_MODE, pub);
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
				try {
					this.new FILE().ProcessFile(ci, inFile, encFile);
				} catch (IllegalBlockSizeException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (BadPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		
		}
		
		public void PrivateKeyEncrypt(PrivateKey pvt, String inFile, String encFile) {
			Cipher ci = null;
			try {
				ci = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			try {
				ci.init(Cipher.ENCRYPT_MODE, pvt);
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
				try {
					this.new FILE().ProcessFile(ci, inFile, encFile);
				} catch (IllegalBlockSizeException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (BadPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		
		}
		/**
		 * Save key to file, but don't prompt user
		 * @param FileName
		 * @throws IOException 
		 * @throws FileNotFoundException 
		 */
		public void SaveKey(byte[] iv,String FileName) throws FileNotFoundException, IOException {
			
			try (FileOutputStream out = new FileOutputStream(FileName)) {
			    try {
					out.write(iv);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		
		/**
		 * First thing's first, secret key gen
		 * @return
		 */
		public IvParameterSpec SecretKeyInit() {
			System.out.println("");
			byte[] iv = new byte[128/8];
			System.out.println("BEFORE:"+iv);
			new Random().nextBytes(iv);
			System.out.println("AFTER:"+iv);
			IvParameterSpec I = new IvParameterSpec(iv);
			
			this.ivspec = I;
			
			return I;
		}
		
		public  SecretKey GenerateSecretKey() {
			KeyGenerator kgen = null;
			try {
				kgen = KeyGenerator.getInstance("AES");
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return kgen.generateKey();
		}

		public void SaveInitializationVector(String ivFile) throws FileNotFoundException, IOException {
			if(ivspec==null) {
				System.err.println("No IVSPEC CREATED!!");
				return;
			}
			// TODO Auto-generated method stub
			try (FileOutputStream out = new FileOutputStream(ivFile)) {
			    try {
					out.write(this.ivspec.getIV());
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		
		
		public Object[] ProcessAfterBytes(File file,int HowMany) throws IOException {
		    
			ArrayList<Byte> All = new ArrayList<Byte>();
			
		
			
			//byte[] result = null;
			
			try (RandomAccessFile data = new RandomAccessFile(file, "r")) {
				 byte[] t2 = new byte[HowMany];
				 
				 System.out.println(data.length());
				 
		      for (long i = 0, len = data.length() / HowMany; i < len; i++) {
		    	
		    	  if(i>0) {
		    	data.readFully(t2);
		        // do something with the 8 bytes
		        //return t2;
		        for(Byte k:t2) {
		        	All.add(k);
		        	System.out.print(k);
	
		        }
		        
		        System.out.println();
		    	}
		    	  
		      }
		    }
			
			return All.toArray();
		  }
		
		public byte[] GetIvSpec(String ivFile) {
			// TODO Auto-generated method stub
			byte[] iv = new byte[16];
	
			//byte[] iv;
			try {
				FileInputStream FIS = new FileInputStream(ivFile);
				
				FIS.read(iv);
				
				FIS.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			/*
			try {
				iv = Files.readAll(Paths.get(ivFile));
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			*/
			
			IvParameterSpec ivspec = new IvParameterSpec(iv);
			
			this.ivspec = ivspec;
			
			return iv;
		}

		public SecretKey LoadAESKey(String keyFile) {
			// TODO Auto-generated method stub
			Object[] keyb = null;
			byte[] kb = null;
			try {
				//keyb = Files.readAllBytes(Paths.get(keyFile));
				keyb = this.ProcessAfterBytes(new File(keyFile), 16);
				kb = new byte[keyb.length];
				for(int i=0; i<keyb.length;i+=1)
					kb[i]=(byte)keyb[i];
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			SecretKeySpec skey = new SecretKeySpec(kb, "AES");
			return skey;
		}
		
	}
	
	
	public class FILE{
		
		public void ProcessFile(Cipher ci,String inFile,String outFile)
			    throws javax.crypto.IllegalBlockSizeException,
		           javax.crypto.BadPaddingException,
		           java.io.IOException
		    {
		        try (FileInputStream in = new FileInputStream(inFile);
		             FileOutputStream out = new FileOutputStream(outFile)) {
		            byte[] ibuf = new byte[1024];
		            int len;
		            while ((len = in.read(ibuf)) != -1) {
		                byte[] obuf = ci.update(ibuf, 0, len);
		                if ( obuf != null ) out.write(obuf);
		            }
		            byte[] obuf = ci.doFinal();
		            if ( obuf != null ) out.write(obuf);
		        }
		    }

		public void DecryptFile(SecretKey skey, IvParameterSpec ivspec,String FileIn,String FileOut) {
			Cipher ci = null;
			try {
				ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			try {
				ci.init(Cipher.DECRYPT_MODE, skey, ivspec);
			} catch (InvalidKeyException | InvalidAlgorithmParameterException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			try {
				ProcessFile(ci, FileIn, FileOut);
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
	}
	
	public static void main(String[] args) throws FileNotFoundException, IOException {
		
		System.out.println("CRYPTYR");
		
		Cryptyr cryptyr = new Cryptyr();
		
		CIPHER cipher = cryptyr.new CIPHER();
		
		KEY key = cryptyr.new KEY();
		
		FILE file = cryptyr.new FILE();
		
		//CIPHER cipher = new CIPHER();
		//FILE file = new FILE();
		
		//
		/* 1. Generating a secret key - GOOD
		 */
		
		
		 /* 2. Encrypting a file using a secret key
		 */
		
		
		/*3. Decrypting a file using a secret key
		 
		 */
		  
		
		 /*4. Encrypting a secret key using a public key
		 */
		 
		
		
		/*
		   5. Decrypting a secret key using a private key
		 */
		
		//Use Skey.getEncoded(); to convert to byte[] so can save to file
		if(args.length>1) {
			
		if(args[0].toLowerCase().compareTo("generatekey")==0) {
			if(args.length==2) {
				System.out.println("Generate Secret Key");
				
				//SecretKey secretkey = key.GenerateSecretKey();
				SecretKey secretkey = key.GenerateAESKey();
				
				byte[][] IVV = new byte[][] {
					key.ivspec.getIV(),
					secretkey.getEncoded()
				};
				byte[] IV = new byte[IVV[0].length + IVV[1].length];
				int k=0;
				for(byte i: IVV[0]) {
					IV[k] = i;
					k+=1;
				}
				for(byte i: IVV[1]) {
					IV[k] = i;
					k+=1;
				}
				
				
				try {
					key.SaveKey(/*secretkey.getEncoded()*/IV, args[1]);
					
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				System.out.println("Finish Generate Secret Key");
			}
		}
		
		if(args[0].toLowerCase().compareTo("encryptfile")==0) {
			if(args.length==4) {
				
				System.out.println("Encrypt file");
				
				
				
				Tuple<SecretKey,Cipher> T  = cryptyr.GetSecretKeyAndCipher(key,args[2],args[1]);
				
				//Tuple<SecretKey,Cipher> T  = cryptyr.GetAESSecretKeyAndCipher(key,args[2],args[1]);
				
				Cipher C = T.Second;
				SecretKey secretkey = T.First;
				
				//IvParameterSpec ivspec = key.SecretKeyInit();
				byte[] ivspec = key.GetIvSpec(args[2]);
				
				key.ivspec=new IvParameterSpec(ivspec);
				
				try {
					try {
						C.init(Cipher.ENCRYPT_MODE, secretkey,key.ivspec);
					} catch (InvalidAlgorithmParameterException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				} catch (InvalidKeyException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
					try {
						file.ProcessFile(C, args[1],args[3]);
					} catch (IllegalBlockSizeException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (BadPaddingException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
						
				
				System.out.println("Successful Encryption Saved to:"+args[3]);
				
				key.SaveInitializationVector(args[2]+".iv");
				
				System.out.println("Successful Save Init Vector Associated with Secret Key:"+args[2]);
				
				}
		}
		if(args[0].toLowerCase().compareTo("decryptfile")==0) {
			if(args.length==4) {
				System.out.println("Decrypt File");
				
				Tuple<SecretKey,Cipher> T  = cryptyr.GetSecretKeyAndCipher(key,args[2],args[1]);
				Cipher C = T.Second;
				SecretKey secretkey = T.First;
	
				byte[]  iv = key.GetIvSpec(args[2]);
				key.ivspec = new IvParameterSpec(iv);
				
				key.AESKeyDecrypt(key.LoadAESKey(args[2]), args[1], args[3]);
				
				/*
				try {
					try {
						C.init(Cipher.DECRYPT_MODE, secretkey,key.ivspec);
					} catch (InvalidAlgorithmParameterException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				} catch (InvalidKeyException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			
				byte[] encoded = Files.readAllBytes(Paths.get(args[1]));
				
				String plainText = null;
				try {
					 plainText = new String(C.doFinal(encoded));
				} catch (IllegalBlockSizeException | BadPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				System.out.println("Successful Decryption OF:\n"+plainText+"\nSaved to:"+args[3]);
				
				FileOutputStream f = new FileOutputStream(args[3]);
				
				f.write(plainText.getBytes());
				
				f.close();
				*/
			}
		}
		
		if(args[0].toLowerCase().compareTo("encryptkey")==0) {
			if(args.length==4) {
				
				System.out.println("PUBLIC Key Encryption");
				
				PublicKey PK = null;
				
				try {
					 PK = key.GetPublicKey(args[2]);
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				key.PublicKeyEncrypt(PK, args[1], args[3]);
				
				System.out.println("Successful Public Key Encryption");
				
			}
		}
		
		if(args[0].toLowerCase().compareTo("decryptkey")==0) {
			if(args.length==4) {
				
				System.out.println("Private Key Decryption");
				
				PrivateKey PK = null;
				
				try {
					PK = key.GetPrivateKey(args[2]);
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				
				key.PrivateKeyDecrypt(PK,args[1], args[3]);
				
				System.out.println("Successful Private Key Decryption");
			}
		}
		
		}
		
	}
	
	
	/*
	private Tuple<SecretKey, Cipher> GetAESSecretKeyAndCipher(KEY key, String string, String string2) {
		Cipher C = null;
		try {
			
			C = Cipher.getInstance("AES/CBC/PKCS5Padding");
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println("Successful Get Cipher and Secret Key");
		
		
		return new Tuple<SecretKey,Cipher>(secretkey,C);
	}
*/


	public Tuple<SecretKey, Cipher> GetSecretKeyAndCipher(KEY key,String SecretKeyFile, String CipherFile){
		

		SecretKey secretkey = key.GetSecretKey(SecretKeyFile);
		Cipher C = null;
		try {
			
			C = Cipher.getInstance("AES/CBC/PKCS5Padding");
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println("Successful Get Cipher and Secret Key");
		
		
		return new Tuple<SecretKey,Cipher>(secretkey,C);
	}
	
	/**
	 * IF string contains .blah, do nothing
	 * else, return string+.blah
	 */
	public static String ConvertExtension(String s,String dot) {
		if(!s.contains(dot)) {
			return s+dot;
		}
		return s;
	}
	
	
	
}
