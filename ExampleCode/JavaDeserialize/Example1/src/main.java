public class main {
    public static void main(String[] args) {

    System.out.println("Serializing...");
    LogFile ob = new LogFile();
    ob.filename = "User_Nytro.log";
    ob.filecontent = "No actoins logged";
    String file = "log.ser";
    Utils.SerializeToFile(ob,file);
    System.out.println("Deserializing...");
    LogFile obd = new LogFile();
    String filed = "log.ser";
    obd=(LogFile)Utils.DeserializeFromFile(filed);
    System.out.println("Desrializing vuln exp...");
    LogFile obv = new LogFile();
    String filev = "Exp.ser";
    obv = (LogFile)Utils.DeserializeFromFile(filev);



    }



}
