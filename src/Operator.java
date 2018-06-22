/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author user
 */

class Operator extends Bot {
  MESSENINE jf = null;
  
  public Operator (MESSENINE jf) {
    this.jf = jf;
  }
  
  void onOpen (String sockName) {
    jf.onOpen(sockName);
    System.out.printf("[open] sockName: %s\n", sockName);
  }

  void onClose (String sockName) {
    jf.onClose(sockName);
    System.out.printf("[close] sockName: %s\n", sockName);
  }

  void onMessage(String sockName, String type, String msg) {
    jf.onMessage(sockName, type, msg);
    System.out.printf("[message] who: %s, type: %s, msg: %s\n", sockName, type, msg);
    switch (type) {
      case "ping": send("pong"); break;
    }
  }
}
