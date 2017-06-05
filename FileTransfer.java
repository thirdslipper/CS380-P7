
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;


public class FileTransfer {
	static Scanner kb = new Scanner(System.in);
	public static void main(String[] args) {
		/*		for (int i = 0; i < args.length; ++i){
			System.out.print(args[i]);
		}
		System.out.println();*/
		switch (args[0].toLowerCase()){
		case "makekeys":
			makeKeys();
			break;
		case "server": //key file, port
			serverMode(args[1], Integer.parseInt(args[2]));
			break;
		case "client":	//key file, host, port
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
		Chunk chunk = null;
		int numChunks = 0;
		Key sessionKey = null;
		boolean canTransfer = false;
		boolean transferDone = false;
		int expSeq = 0;
		ArrayList<byte[]> data = new ArrayList<byte[]>();

		Key privateKey = getKey(privateKeyFile);
		try {
			ServerSocket server = new ServerSocket(port);
			Socket socket = server.accept();

			ois = new ObjectInputStream(socket.getInputStream());	
			oos = new ObjectOutputStream(socket.getOutputStream());

			while (true){
				msg = (Message) ois.readObject();

				if (msg instanceof DisconnectMessage){
					server.close();
					server.accept();
				}
				if (msg instanceof StartMessage && start == null){
					System.out.println("Received StartMessage");
					start = (StartMessage) msg;

					Cipher cipher = Cipher.getInstance("RSA");	//Unwrap client's key
					cipher.init(Cipher.UNWRAP_MODE, privateKey);
					sessionKey = cipher.unwrap(start.getEncryptedKey(), "AES", Cipher.SECRET_KEY);
					
					canTransfer = true;
					oos.writeObject(new AckMessage(0));	
				}
				if (msg instanceof StopMessage){
					canTransfer = false;
					oos.writeObject(new AckMessage(-1));
				}
				if (msg instanceof Chunk && canTransfer && !transferDone){
					chunk = (Chunk) msg;
					numChunks = (int) Math.ceil(((double)start.getSize()/(double)start.getChunkSize()));
					
					System.out.println("Expected Chunk#: " + (expSeq+1) + " Received Chunk#: " + (chunk.getSeq()+1)
							+ "/" + numChunks);
					if (expSeq == chunk.getSeq()){	//seq checking

						Cipher cipher = Cipher.getInstance("AES");	//decrypt key
						cipher.init(Cipher.DECRYPT_MODE, sessionKey);
						byte[] encryptedChunk = cipher.doFinal(chunk.getData());
						
						if (checksum(encryptedChunk) == chunk.getCrc()){	//compare crc
							++expSeq;	//inc expected sequence num
							data.add(encryptedChunk); //store data
							oos.writeObject(new AckMessage(expSeq));	//respond with ack of next chunk
						}
					}
					if (expSeq == numChunks){
						System.out.println();
						transferDone = true;
						canTransfer = false;
					}
				}
			}
		} catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			try {
				oos.writeObject(new AckMessage(-1));
			} catch (IOException e1) {
				e1.printStackTrace();
			}
		}
	}

	public static void clientMode(String publicKeyFile, String host, int port){
		byte[] fileData = null;
		try {	
			Socket socket = null;
			try {
				socket = new Socket(host, 80);
				System.out.println("Connected to server: " + host + "/" + socket.getInetAddress().getHostAddress());
			} catch (IOException e) {
				e.printStackTrace();
			}
			ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
			ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

			KeyGenerator keyGen = KeyGenerator.getInstance("AES");	//get session key
			keyGen.init(128);
			SecretKey secretKey = keyGen.generateKey();
			Cipher cipher = Cipher.getInstance("RSA");	//get public key wrap
			Key publicKey = getKey(publicKeyFile);
			cipher.init(Cipher.WRAP_MODE, publicKey);

			byte[] wrappedKey = cipher.wrap(secretKey);	//wrap session key in public key
			String filepath = getFilePath();
			int fileSize = (int) new File(filepath).length();
			int chunkSize = getChunks();
			int numChunks = (int) Math.ceil((double) fileSize/(double) chunkSize);

			System.out.println("Sending: " + filepath + "\tFile size: " + fileSize
					+ "\nSending " + numChunks + " chunks.");

			oos.writeObject(new StartMessage(filepath, wrappedKey, chunkSize));	//send start
			Message received = (Message) ois.readObject();	//receive ack 0

			boolean nextChunk = true;
			fileData = getData(filepath, fileSize);		//get file data
			byte[] chunk = null;
			byte[] encryptChunk = null;
			Cipher encrypt = Cipher.getInstance("AES");
			encrypt.init(Cipher.ENCRYPT_MODE, secretKey);
			Message ack = null;

			for (int i = 0; i < numChunks; ++i){
				if(nextChunk == true){
					if ((i+1)*chunkSize-1 < numChunks){	//partition chunks
						chunk = Arrays.copyOfRange(fileData, i*chunkSize, (i+1)*chunkSize-1);
					}
					else{
						chunk = Arrays.copyOfRange(fileData, i*chunkSize, fileSize-1);
					}
					encryptChunk = encrypt.doFinal(chunk);	//encrypt chunk
					oos.writeObject(new Chunk(i, encryptChunk, checksum(chunk)));	//send chunk 0-numChunks
//					System.out.println("Chunk #: " + i + " sent.");

					ack = (Message) ois.readObject();	//receive ack 1-(numChunks+1)
					if (ack instanceof AckMessage){
						if (((AckMessage) ack).getSeq() == (i+1)){
							System.out.println("\tAck Received");
						}
						else{
							nextChunk = false;
						}
					}
					System.out.println("Chunks completed [" + (i+1) + "/" + numChunks + "].");
				}
			}
			if (((AckMessage) ack).getSeq() == (numChunks)){
				System.out.println("Transfer complete.");
			}
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | IOException | ClassNotFoundException | BadPaddingException e) {
			e.printStackTrace();
		}
	}
	public static byte[] getData(String filepath, int fileSize){
		byte[] data = new byte[fileSize];

		try {
			FileInputStream fis = new FileInputStream(new File(filepath));
			for (int i = 0; i < fileSize; ++i){
				data[i] = (byte) fis.read();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return data;
	}
	public static String getFilePath(){
		String filepath = "";
		boolean valid = false;
		while (!valid){
			System.out.println("Enter path: ");
			filepath = kb.nextLine();
			if (new File(filepath).exists()){
				valid = true;
			}
		}
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
	public static int getChunks(){
		System.out.println("Enter chunk size [1024]: ");
		String chunks = kb.nextLine();
		if (chunks.equals("")){
			return 1024;
		}
		return Integer.parseInt(chunks);
	}
	public static short checksum(byte[] b){
		long concat = 0x0;
		long sum = 0x0;
		for (int i = 0; i < b.length; i+=2){
			concat = (long) (b[i] & 0xFF);
			concat <<= 8;

			if ((i+1) < b.length){
				concat |= (b[i+1] & 0xFF);
			}
			sum = sum + concat;
			if (sum > 0xFFFF){
				sum &= 0xFFFF;
				sum ++;
			}
		}
		short checksum = (short) (~sum);
		//		System.out.println("Checksum calculated: 0x" + Integer.toHexString(checksum & 0xFFFF).toUpperCase());
		return (short) (~sum);
	}
}
