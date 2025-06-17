const int GREEN_LED = 10;
const int RED_LED = 11;
const int BUZZER = 12;

String inputString = "";
bool stringComplete = false;
unsigned long lastAlertTime = 0;
const unsigned long ALERT_DURATION = 3000;
const unsigned long BATCH_ALERT_DURATION = 5000;
bool isConnected = false;

void setup() {
  Serial.begin(9600);
  pinMode(GREEN_LED, OUTPUT);
  pinMode(RED_LED, OUTPUT);
  pinMode(BUZZER, OUTPUT);
  
  digitalWrite(GREEN_LED, LOW);
  digitalWrite(RED_LED, LOW);
  digitalWrite(BUZZER, LOW);
  
  Serial.println("Arduino Ransomware Alert System Ready");
  Serial.flush();
  
  startupSequence();
  isConnected = true;
}

void loop() {
  if (stringComplete) {
    processCommand(inputString);
    inputString = "";
    stringComplete = false;
  }
  
  handleAlertTimeout();
  
  // Handle connection status
  if (isConnected && millis() > 10000) { // After 10 seconds of startup
    // System is ready and waiting for commands
  }
}

void serialEvent() {
  while (Serial.available()) {
    char inChar = (char)Serial.read();
    if (inChar == '\n') {
      stringComplete = true;
    } else if (inChar != '\r') { // Ignore carriage return
      inputString += inChar;
    }
  }
}

void processCommand(String command) {
  command.trim();
  Serial.println("Received: " + command);
  Serial.flush();
  
  if (command == "BENIGN") {
    handleBenignDetection();
  } 
  else if (command == "RANSOMWARE") {
    handleRansomwareDetection();
  }
  else if (command.startsWith("BATCH_MALICIOUS:")) {
    handleBatchMalicious(command);
  }
  else if (command == "BATCH_CLEAN") {
    handleBatchClean();
  }
  else if (command == "STATUS") {
    handleStatusRequest();
  }
  else if (command == "RESET") {
    handleReset();
  }
  else {
    Serial.println("Unknown command: " + command);
    Serial.flush();
  }
}

void handleBenignDetection() {
  Serial.println("Status: File is BENIGN");
  Serial.flush();
  clearAllAlerts();
  
  // Sweet melody for benign detection
  playBenignMelody();
  
  digitalWrite(GREEN_LED, HIGH);
  lastAlertTime = millis();
}

void handleRansomwareDetection() {
  Serial.println("ALERT: RANSOMWARE DETECTED!");
  Serial.flush();
  clearAllAlerts();
  
  // Flash red LED with buzzer pattern for ransomware alert
  for (int i = 0; i < 3; i++) {
    digitalWrite(RED_LED, HIGH);
    tone(BUZZER, 1000);
    delay(200);
    digitalWrite(RED_LED, LOW);
    noTone(BUZZER);
    delay(200);
  }
  
  // Keep red LED on and buzzer sounding
  digitalWrite(RED_LED, HIGH);
  tone(BUZZER, 1000);
  lastAlertTime = millis();
}

void handleBatchMalicious(String command) {
  Serial.println("BATCH ALERT: Malicious files detected in batch");
  Serial.flush();
  clearAllAlerts();
  
  int colonIndex = command.indexOf(':');
  String countInfo = command.substring(colonIndex + 1);
  Serial.println("Batch result: " + countInfo);
  Serial.flush();
  
  // Extended alert sequence for batch detection
  for (int i = 0; i < 5; i++) {
    digitalWrite(RED_LED, HIGH);
    tone(BUZZER, 800 + (i * 100)); // Ascending tone
    delay(300);
    digitalWrite(RED_LED, LOW);
    noTone(BUZZER);
    delay(200);
  }
  
  // Final sustained alert
  digitalWrite(RED_LED, HIGH);
  tone(BUZZER, 1500);
  lastAlertTime = millis();
}

void handleBatchClean() {
  Serial.println("BATCH COMPLETE: All files clean");
  Serial.flush();
  clearAllAlerts();
  
  // Visual indicator with success melody
  for (int i = 0; i < 3; i++) {
    digitalWrite(GREEN_LED, HIGH);
    delay(150);
    digitalWrite(GREEN_LED, LOW);
    delay(100);
  }
  
  // Play success melody
  playSuccessMelody();
  
  // Keep green LED on
  digitalWrite(GREEN_LED, HIGH);
  lastAlertTime = millis();
}

void handleStatusRequest() {
  Serial.println("Arduino Status: READY");
  Serial.print("Green LED: ");
  Serial.println(digitalRead(GREEN_LED) ? "ON" : "OFF");
  Serial.print("Red LED: ");
  Serial.println(digitalRead(RED_LED) ? "ON" : "OFF");
  Serial.flush();
}

void handleReset() {
  Serial.println("Resetting system...");
  Serial.flush();
  clearAllAlerts();
  lastAlertTime = 0;
  startupSequence();
  Serial.println("System reset complete");
  Serial.flush();
}

void handleAlertTimeout() {
  unsigned long currentTime = millis();
  unsigned long duration = ALERT_DURATION;
  
  // Use longer duration for red LED (malicious) alerts
  if (digitalRead(RED_LED) == HIGH) {
    duration = BATCH_ALERT_DURATION;
  }
  
  if (lastAlertTime > 0 && (currentTime - lastAlertTime > duration)) {
    clearAllAlerts();
    lastAlertTime = 0;
    Serial.println("Alert timeout - clearing all indicators");
    Serial.flush();
  }
}

void clearAllAlerts() {
  digitalWrite(GREEN_LED, LOW);
  digitalWrite(RED_LED, LOW);
  noTone(BUZZER);
}

void playBenignMelody() {
  // Sweet ascending melody for benign files
  int melody[] = {523, 587, 659, 698, 784}; // C5, D5, E5, F5, G5
  int noteDurations[] = {200, 200, 200, 200, 400};
  
  for (int i = 0; i < 5; i++) {
    tone(BUZZER, melody[i]);
    delay(noteDurations[i]);
    noTone(BUZZER);
    delay(50); // Short pause between notes
  }
}

void playSuccessMelody() {
  // Happy success tune for clean batches
  int melody[] = {659, 659, 784, 1047, 784, 659}; // E5, E5, G5, C6, G5, E5
  int noteDurations[] = {150, 150, 200, 300, 200, 400};
  
  for (int i = 0; i < 6; i++) {
    tone(BUZZER, melody[i]);
    delay(noteDurations[i]);
    noTone(BUZZER);
    delay(30);
  }
}

void startupSequence() {
  Serial.println("Starting system check...");
  Serial.flush();
  
  // Test green LED
  digitalWrite(GREEN_LED, HIGH);
  delay(500);
  digitalWrite(GREEN_LED, LOW);
  
  // Test red LED
  digitalWrite(RED_LED, HIGH);
  delay(500);
  digitalWrite(RED_LED, LOW);
  
  // Test buzzer
  tone(BUZZER, 1000);
  delay(200);
  noTone(BUZZER);
  
  Serial.println("System check complete - Ready for detection");
  Serial.flush();
}