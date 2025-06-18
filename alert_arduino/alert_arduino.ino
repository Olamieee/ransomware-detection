const int GREEN_LED = 3;
const int RED_LED = 8;
const int BUZZER = 13;

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
  else if (command == "TEST_GREEN") {
    testGreenLED();
  }
  else if (command == "TEST_RED") {
    testRedLED();
  }
  else {
    Serial.println("Unknown command: " + command);
    Serial.flush();
  }
}

void testGreenLED() {
  Serial.println("Testing GREEN LED on pin 3...");
  Serial.flush();
  clearAllAlerts();
  
  // Flash green LED 5 times
  for (int i = 0; i < 5; i++) {
    digitalWrite(GREEN_LED, HIGH);
    Serial.println("GREEN LED ON");
    delay(500);
    digitalWrite(GREEN_LED, LOW);
    Serial.println("GREEN LED OFF");
    delay(500);
  }
  Serial.println("GREEN LED test complete");
  Serial.flush();
}

void testRedLED() {
  Serial.println("Testing RED LED on pin 8...");
  Serial.flush();
  clearAllAlerts();
  
  // Flash red LED 5 times
  for (int i = 0; i < 5; i++) {
    digitalWrite(RED_LED, HIGH);
    Serial.println("RED LED ON");
    delay(500);
    digitalWrite(RED_LED, LOW);
    Serial.println("RED LED OFF");
    delay(500);
  }
  Serial.println("RED LED test complete");
  Serial.flush();
}

void handleBenignDetection() {
  Serial.println("Status: File is BENIGN - GREEN LED ON");
  Serial.flush();
  clearAllAlerts();
  
  // First, test the green LED explicitly
  digitalWrite(GREEN_LED, HIGH);
  Serial.println("GREEN LED should be ON now");
  Serial.flush();
  
  // Soft confirmation beep for benign detection
  playSafeFileSound();
  
  // Ensure green LED stays on
  digitalWrite(GREEN_LED, HIGH);
  lastAlertTime = millis();
  
  Serial.println("GREEN LED status after benign detection: ON");
  Serial.flush();
}

void handleRansomwareDetection() {
  Serial.println("ALERT: RANSOMWARE DETECTED!");
  Serial.flush();
  clearAllAlerts();
  
  // Critical ransomware alert sequence
  playRansomwareAlert();
  
  // Keep red LED on and buzzer sounding
  digitalWrite(RED_LED, HIGH);
  tone(BUZZER, 800); // Persistent warning tone
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
  
  // Multiple threat alert sequence
  playBatchMaliciousAlert();
  
  // Final sustained alert
  digitalWrite(RED_LED, HIGH);
  tone(BUZZER, 900); // Higher pitch for batch threats
  lastAlertTime = millis();
}

void handleBatchClean() {
  Serial.println("BATCH COMPLETE: All files clean - GREEN LED ON");
  Serial.flush();
  clearAllAlerts();
  
  // Visual indicator with success melody
  for (int i = 0; i < 3; i++) {
    digitalWrite(GREEN_LED, HIGH);
    Serial.println("GREEN LED flash ON");
    delay(150);
    digitalWrite(GREEN_LED, LOW);
    Serial.println("GREEN LED flash OFF");
    delay(100);
  }
  
  // Play all-clear confirmation
  playBatchCleanSound();
  
  // Keep green LED on
  digitalWrite(GREEN_LED, HIGH);
  Serial.println("GREEN LED final state: ON");
  lastAlertTime = millis();
  Serial.flush();
}

void handleStatusRequest() {
  Serial.println("Arduino Status: READY");
  Serial.print("Green LED (Pin 3): ");
  Serial.println(digitalRead(GREEN_LED) ? "ON" : "OFF");
  Serial.print("Red LED (Pin 8): ");
  Serial.println(digitalRead(RED_LED) ? "ON" : "OFF");
  Serial.print("Buzzer (Pin 13): ");
  Serial.println("Ready");
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

void playSafeFileSound() {
  // Two gentle confirmation beeps for safe files
  tone(BUZZER, 400);  // Low, reassuring tone
  delay(150);
  noTone(BUZZER);
  delay(100);
  tone(BUZZER, 500);  // Slightly higher confirmation
  delay(200);
  noTone(BUZZER);
}

void playRansomwareAlert() {
  // Critical security alert pattern - urgent and attention-grabbing
  for (int cycle = 0; cycle < 4; cycle++) {
    // Rapid high-pitched alarm bursts
    for (int burst = 0; burst < 3; burst++) {
      digitalWrite(RED_LED, HIGH);
      tone(BUZZER, 1500); // High urgency tone
      delay(150);
      digitalWrite(RED_LED, LOW);
      noTone(BUZZER);
      delay(50);
    }
    
    // Brief pause between cycles
    delay(200);
    
    // Secondary warning tone
    digitalWrite(RED_LED, HIGH);
    tone(BUZZER, 1000); // Lower warning tone
    delay(300);
    digitalWrite(RED_LED, LOW);
    noTone(BUZZER);
    delay(150);
  }
}

void playBatchMaliciousAlert() {
  // Escalating threat level alert for multiple malicious files
  digitalWrite(RED_LED, HIGH);
  
  // Siren-like warning pattern
  for (int sweep = 0; sweep < 3; sweep++) {
    // Rising siren
    for (int freq = 600; freq <= 1200; freq += 50) {
      tone(BUZZER, freq);
      delay(30);
    }
    // Falling siren
    for (int freq = 1200; freq >= 600; freq -= 50) {
      tone(BUZZER, freq);
      delay(30);
    }
  }
  
  digitalWrite(RED_LED, LOW);
  noTone(BUZZER);
  delay(200);
  
  // Final urgent pulses
  for (int pulse = 0; pulse < 5; pulse++) {
    digitalWrite(RED_LED, HIGH);
    tone(BUZZER, 1400);
    delay(100);
    digitalWrite(RED_LED, LOW);
    noTone(BUZZER);
    delay(100);
  }
}

void playBatchCleanSound() {
  // Professional "all clear" confirmation sequence
  // Three descending tones indicating security cleared
  tone(BUZZER, 800);
  delay(200);
  noTone(BUZZER);
  delay(100);
  
  tone(BUZZER, 600);
  delay(250);
  noTone(BUZZER);
  delay(100);
  
  tone(BUZZER, 450);
  delay(400);
  noTone(BUZZER);
  delay(200);
  
  // Final confirmation beep
  tone(BUZZER, 500);
  delay(150);
  noTone(BUZZER);
}

void startupSequence() {
  Serial.println("Starting system check...");
  Serial.flush();
  
  // System initialization sound
  tone(BUZZER, 600);
  delay(200);
  tone(BUZZER, 800);
  delay(200);
  noTone(BUZZER);
  
  // Test green LED
  Serial.println("Testing GREEN LED (Pin 3)...");
  digitalWrite(GREEN_LED, HIGH);
  delay(1000);  // Longer delay to see it clearly
  digitalWrite(GREEN_LED, LOW);
  
  // Test red LED
  Serial.println("Testing RED LED (Pin 8)...");
  digitalWrite(RED_LED, HIGH);
  delay(1000);
  digitalWrite(RED_LED, LOW);
  
  // Test buzzer with security system ready tone
  Serial.println("Testing BUZZER (Pin 13)...");
  tone(BUZZER, 1000);
  delay(150);
  noTone(BUZZER);
  delay(100);
  tone(BUZZER, 1200);
  delay(150);
  noTone(BUZZER);
  delay(100);
  tone(BUZZER, 800);
  delay(300);
  noTone(BUZZER);
  
  Serial.println("System check complete - Ready for detection");
  Serial.flush();
}