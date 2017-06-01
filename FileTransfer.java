import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;


public class FileTransfer {
	public static void main(String[] args) {
		for (int i = 0; i < args.length; ++i){
			System.out.print(args[i]);
		}
		switch (args[0]){
		case "makekeys":
			makeKeys();
			break;
		case "server":
			serverMode(args[1], Integer.parseInt(args[2]));
			break;
		case "client":
			clientMode(args[1], args[2], Integer.parseInt(args[3]));
			break;
		}
	}
	
	public static void makeKeys(){
		try {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(2048); // or 4096
			KeyPair keyPair = gen.genKeyPair();
			PrivateKey privateKey = keyPair.getPrivate();

			PublicKey publicKey = keyPair.getPublic();
			try (ObjectOutputStream oos = new ObjectOutputStream(
					new FileOutputStream(new File("public.bin")))) {
				oos.writeObject(publicKey);
			}
			try (ObjectOutputStream oos = new ObjectOutputStream(
					new FileOutputStream(new File("private.bin")))) {
				oos.writeObject(privateKey);
			}
		} catch (NoSuchAlgorithmException | IOException e) {
			e.printStackTrace(System.err);
		}
	}
	
	public static void serverMode(String privateKeyFile, int port){
		ObjectInputStream ois = null;
		ObjectOutputStream oos = null;
		Message msg = null;
		StartMessage start = null;
		Key sessionKey = null;
		Boolean canTransfer = false;

		Key privateKey = getKey(privateKeyFile);
		try {
			ServerSocket server = new ServerSocket(port);
			Socket socket = server.accept();
			ois = new ObjectInputStream(socket.getInputStream());
			oos = new ObjectOutputStream(socket.getOutputStream());
			msg = (Message) ois.readObject();

			if (msg instanceof DisconnectMessage){
				server.close();
				server.accept();
			}
			else if (msg instanceof StartMessage && start == null){
				start = (StartMessage) msg;
				Cipher cipher = Cipher.getInstance("AES");
				cipher.init(Cipher.UNWRAP_MODE, privateKey);
				sessionKey = cipher.unwrap(start.getEncryptedKey(), "AES", Cipher.PUBLIC_KEY);
				canTransfer = true;
				oos.writeObject(new AckMessage(0));
				//	oos.writeObject(new AckMessage(-1));
			}
			else if (msg instanceof StopMessage){
				canTransfer = false;
				//discard file transfer
			}
			else if (msg instanceof Chunk && canTransfer){
				receiveChunks(start, ois, oos);
				
			}
		} catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			e.printStackTrace();
		}
	}
	
	public static int receiveChunks(StartMessage start, ObjectInputStream ois, ObjectOutputStream oos){
		int expSeq = 0;
		Message chunk = null;
		try {
			Cipher cipher = Cipher.getInstance("AES");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		for (int i = 0; i < start.getChunkSize(); ++i){
			try {
				chunk = (Message) ois.readObject();
			} catch (ClassNotFoundException | IOException e) {
				e.printStackTrace();
			}
			if (chunk instanceof Chunk){
				if (((Chunk) chunk).getSeq() == expSeq){
					
				}
			}
		}
		return 0;
	}
	public static void clientMode(String publicKeyFile, String host, int port){
		try {	//get key from file?
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(256);
			SecretKey secretKey = keyGen.generateKey();

			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.WRAP_MODE, secretKey);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			e.printStackTrace();
		}
		String filepath = getFilePath();


	}
	public static String getFilePath(){
		Scanner kb = new Scanner(System.in);
		String filepath = "";
		boolean valid = false;
		while (!valid){
			System.out.println("Enter path for a file to transfer: ");
			filepath = kb.nextLine();
			if (new File(filepath).exists()){
				valid = true;
			}
		}
		kb.close();
		return filepath;
	}
	public static Key getKey(String filename){
		Key key = null;
		try {
			ObjectInputStream ois = new ObjectInputStream(new FileInputStream(new File(filename)));
			key = (Key) ois.readObject();
			ois.close();
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}
		return key;
	}
}
