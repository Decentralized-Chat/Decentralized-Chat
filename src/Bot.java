/*
  Source code copied and modified from
  http://www.java2s.com/Tutorials/Java/Java_Network/0070__Java_Network_Non-Blocking_Socket.htm
*/

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.InterfaceAddress;
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.SocketAddress;
import java.net.NetworkInterface;
import java.nio.ByteBuffer;
import java.nio.channels.Channel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.DatagramChannel;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.util.Iterator;
import java.util.Set;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;
import java.util.Enumeration;
import java.util.Collections;
/*from ww w .j a  va  2  s . co m*/

abstract class Bot implements Runnable {
  private Map<String, SocketChannel> connections = new HashMap<>();
  private Selector selectors = null;
  private ServerSocketChannel tcpServer = null;
  private DatagramChannel udpServer = null;
  private InetAddress broadcastAddr = null;
  private Set<InetAddress> inetAddr = new HashSet<>();
  private InetAddress listenAddr = null;
  private int listenPort = 0;
  private Thread thread = null;
  private boolean running = false;
  private String totpSecret = "----magic----";
  private int totpAcceptDelay = 1;
  private String buffer = "";

  abstract void onOpen (String sockName);
  abstract void onClose (String sockName);
  abstract void onMessage (String sockName, String type, String msg);

  public boolean isRunning () {
    return running;
  }

  public void send (String msg) {
    send("text", msg);
  }

  public void send (String type, String msg) {
    for (Map.Entry<String, SocketChannel> ent : connections.entrySet()) {
      write(ent.getKey(), type + ":" + msg);
    }
  }

  public void send (String sockName, String type, String msg) {
    if (! connections.containsKey(sockName)) {
      return;
    }

    write(sockName, type + ":" + msg);
  }

  public void launch (String host, int port) {
    running = true;
    try {
      listen(host, port);
    } catch (Exception e) {
      running = false;
    }
  }

  public void die () {
    if (! running) {
      return;
    }

    for (Map.Entry<String, SocketChannel> ent : connections.entrySet()) {
      try {
        ent.getValue().close();
      } catch (Exception e) {
        System.out.printf("[ERROR] when close %s\n", ent.getKey());
      }
    }

    connections.clear();
    try {
      tcpServer.socket().setReuseAddress(true);
      tcpServer.close();
      udpServer.socket().setReuseAddress(true);
      udpServer.close();
      selectors.close();
      thread.stop();
    } catch (Exception e) {
      System.out.printf("[ERROR] when close server\n");
    }

    running = false;
    System.out.printf("[log] sleeping.\n");
  }

  private void write (String sockName, String data) {
    try {
      connections.get(sockName).write(ByteBuffer.wrap((data.length() + ":" + data).getBytes("UTF-8")));
    } catch (Exception e) {
      System.out.printf("[ERROR] when send to %s\n", sockName);
    }
  }

  private void onData (String sockName, String data) throws Exception {
    buffer += data;
    String line;
    while ((line = chunkData()) != null) {
      String type = null, msg = null;
      int first = -1;

      first = line.indexOf(':');
      if (first == -1) {
        return;
      }

      type = line.substring(0, first);
      msg = line.substring(first + 1);

      System.out.printf("%s, %s\n", type, msg);
      onMessage(sockName, type, msg);
    }
  }

  private String chunkData () {
    System.out.println("### chunkData, buffer = " + buffer);
    int first = buffer.indexOf(':');
    if (first == -1) {
      return null;
    }

    System.out.println("### chunkData, first = " + first);
    int datalen;
    int totalen;
    try {
      datalen = Integer.parseInt(buffer.substring(0, first));
      totalen = datalen + first + 1;
    } catch (Exception e) {
      System.out.printf("[ERROR] when chunkData, clear buffer.\n");
      return null;
    }

    if (buffer.length() < totalen) {
      return null;
    } 

    String ret = buffer.substring(first + 1, totalen);
    if (buffer.length() > totalen) {
      buffer = buffer.substring(totalen);
    } else {
      buffer = "";
    }

    return ret;
  }

  private void serverSelect (Set readySet) throws Exception {
    for (Iterator i = readySet.iterator(); i.hasNext();) {
      SelectionKey key = (SelectionKey) i.next();
      i.remove();
      if (key.isConnectable()) {
        SocketChannel client = (SocketChannel) key.channel();
        String sockName = client.getRemoteAddress().toString();
        if (! processConnect(key)) {
          client.close();
          connections.remove(sockName);
          onClose(sockName);
          System.out.printf("[ERROR] fail to connect to %s.\n", sockName);
          return; // Exit
        }

        client.register(selectors, SelectionKey.OP_READ);
        onOpen(sockName);
      }

      if (key.isAcceptable()) {
        SocketChannel client = (SocketChannel) tcpServer.accept();
        String sockName = client.getRemoteAddress().toString();
        client.configureBlocking(false);
        client.register(selectors, SelectionKey.OP_READ);
        connections.put(sockName, client);
        onOpen(sockName);
        System.out.printf("[socket] open from %s\n", sockName);
      }

      if (key.isReadable()) {
        Channel channel = (Channel) key.channel();
        if (channel == udpServer) {
          ByteBuffer buf = ByteBuffer.allocate(1600);
          InetSocketAddress clientSockAddr = (InetSocketAddress) udpServer.receive(buf);
          InetAddress clientIP = clientSockAddr.getAddress();
          String magic = byteBuffer2String(buf);
          System.out.printf("[UDP] from %s get: %s\n", clientSockAddr.toString(), magic);
          TOTP totp = new TOTP(totpSecret, totpAcceptDelay);
          if (totp.checkToken(magic) && (! inetAddr.contains(clientIP))) {
            connect(clientIP, listenPort);
          }
        } else {
          SocketChannel client = (SocketChannel) channel;
          String sockName = client.getRemoteAddress().toString();

          String msg = processRead(client);
          if (msg == null) {
            client.close();
            onClose(sockName);
            connections.remove(sockName);
            System.out.printf("[log] get null, close socket\n");
            return;
          }

          System.out.printf("[data] from %s: %s\n", sockName, msg);
          try {
            onData(sockName, msg);
          } catch (Exception e) {
            System.out.printf("[ERROR] when handle data %s\n", sockName);
          }
        }
      }
    }
  }

  private static String processRead(SocketChannel channel) {
    ByteBuffer buffer = ByteBuffer.allocate(1024);
    int bytesCount = 0;
    try {
      bytesCount = channel.read(buffer);
    } catch (Exception e) {
      System.out.printf("[ERROR] when read.\n");
      return null;
    }

    if (bytesCount < 1) {
      return null;
    }

    buffer.flip();
    return byteBuffer2String(buffer);
  }

  private static String byteBuffer2String (ByteBuffer buffer) {
    String data = null;
    try {
      data = new String(buffer.array(), "UTF-8");
    } catch (Exception e) {
      System.out.printf("[ERROR] when decode to UTF-8.\n");
    }

    int end = data.indexOf('\0');
    if (end != -1) {
      data = data.substring(0, end);
    }

    return data;
  }

  private static boolean processConnect(SelectionKey key) throws Exception{
    SocketChannel channel = (SocketChannel) key.channel();
    while (channel.isConnectionPending()) {
      try {
        channel.finishConnect();
      } catch (Exception e) {
        return false;
      }
    }
    return true;
  }


  private boolean getNetwork () throws Exception {
    Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
    while(en.hasMoreElements()) {
        NetworkInterface ni = en.nextElement();
        if (ni.isLoopback()) {
          continue;
        }

        Enumeration<InetAddress> ee = ni.getInetAddresses();

        if (broadcastAddr == null) {
            for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                broadcastAddr = ia.getBroadcast();
                if (broadcastAddr != null) {
                    break;
                }
            }
        }

        for (InetAddress inetAddress : Collections.list(ee)) {
            inetAddr.add(inetAddress);
            System.out.println("My self inetAddress: "+inetAddress);
        }
    }
    if (broadcastAddr == null) {
        return false;
    } else {
        return true;
    }
  }

  private void listen (String host, int port) throws Exception {
    InetAddress hostIPAddress = InetAddress.getByName(host);
    InetSocketAddress addr = new InetSocketAddress(hostIPAddress, port);
    if (! getNetwork()) {
      System.out.println("[ERORR] when get network IPs.\n");
      return;
    }

    listenAddr = hostIPAddress;
    listenPort = port;
    selectors = Selector.open();
    tcpServer = (ServerSocketChannel) ServerSocketChannel.open();
    udpServer = (DatagramChannel) DatagramChannel.open();
    tcpServer.configureBlocking(false);
    udpServer.configureBlocking(false);
    tcpServer.socket().bind(addr);
    udpServer.socket().bind(addr);
    tcpServer.register(selectors, SelectionKey.OP_ACCEPT);
    udpServer.register(selectors, SelectionKey.OP_READ);
    TOTP totp = new TOTP(totpSecret, totpAcceptDelay);
    String totpToken = totp.getToken();
    broadcast(listenPort, totpToken);
    thread = new Thread(this);
    thread.start();
  }

  public void run () {
    System.out.printf("[log] running at %s:%d\n", listenAddr, listenPort);
    try {
      while (true) {
        if (selectors.select() <= 0) {
          break;
          // continue;
        }

        serverSelect(selectors.selectedKeys());
      }
    } catch (Exception e) {
      System.out.printf("[ERROR] when run in thread.\n");
      running = false;
    }
  }

  public void connect (String host, int port) throws Exception {
    connect(InetAddress.getByName(host), port);
  }

  public void connect (InetAddress host, int port) throws Exception {
    connect(new InetSocketAddress(host, port));
  }

  public void connect (InetSocketAddress sockAddr) throws Exception {
    if (connections.containsKey(sockAddr.toString())) {
      System.out.printf("[ERROR] to self.\n");
      return;
    }
    SocketChannel channel = SocketChannel.open();
    channel.configureBlocking(false);
    channel.connect(sockAddr);
    channel.register(selectors, SelectionKey.OP_CONNECT | SelectionKey.OP_READ);
    String sockName = channel.getRemoteAddress().toString();
    connections.put(sockName, channel);
    // onOpen(sockName);
    System.out.printf("[connect] to %s\n", sockName);
  }

  public void broadcast (int port, String msg) throws Exception {
    byte[] buf = msg.getBytes();
    DatagramPacket packet = new DatagramPacket(buf, buf.length, broadcastAddr, port);
    DatagramSocket socket = new DatagramSocket();
    socket.send(packet);
    socket.close();
  }

}
