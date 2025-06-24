/*
 * Arduino Ransomware Detection Alert System - UPDATED VERSION
 * Includes Green LED flashing + soft beep for benign files
 */

// Pin definitions
const int RED_LED_PIN = 8;     // Red LED for malicious files
const int GREEN_LED_PIN = 3;   // Green LED for benign files
const int BUZZER_PIN = 13;     // Buzzer for audio alerts

// Timing constants
const unsigned long RANSOMWARE_ALERT_DURATION = 5000;  // 5 seconds for ransomware alert
const unsigned long BUZZER_BEEP_DURATION = 200;        // 200ms beep duration
const unsigned long BUZZER_PAUSE_DURATION = 100;       // 100ms pause between beeps
const int MAX_BUZZER_BEEPS = 10;

// State variables
unsigned long alertStartTime = 0;
unsigned long lastBuzzerTime = 0;
bool isRansomwareAlert = false;
bool buzzerState = false;
int buzzerBeepCount = 0;

// String buffer for serial commands
String inputString = "";
bool stringComplete = false;

void setup() {
  Serial.begin(9600);

  pinMode(RED_LED_PIN, OUTPUT);
  pinMode(GREEN_LED_PIN, OUTPUT);
  pinMode(BUZZER_PIN, OUTPUT);

  digitalWrite(RED_LED_PIN, LOW);
  digitalWrite(GREEN_LED_PIN, LOW);
  digitalWrite(BUZZER_PIN, LOW);

  inputString.reserve(50);

  startupSequence();

  Serial.println("Arduino Ransomware Detector Ready");
  Serial.println("Waiting for commands...");
  Serial.flush();
}

void loop() {
  handleSerialInput();
  updateAlerts();
  delay(10);
}

void handleSerialInput() {
  while (Serial.available()) {
    char inChar = (char)Serial.read();
    if (inChar == '\n' || inChar == '\r') {
      if (inputString.length() > 0) {
        stringComplete = true;
      }
    } else if (inChar >= 32) {
      inputString += inChar;
    }
  }

  if (stringComplete) {
    processCommand(inputString);
    inputString = "";
    stringComplete = false;
  }
}

void processCommand(String command) {
  command.trim();
  command.toUpperCase();

  Serial.print("🔍 Received command: '");
  Serial.print(command);
  Serial.println("'");

  if (command == "RANSOMWARE") {
    triggerRansomwareAlert();
  } else if (command == "BENIGN") {
    triggerBenignAlert();
  } else if (command == "TEST") {
    runSystemTest();
  } else if (command == "STOP" || command == "OFF") {
    stopAllAlerts();
  } else if (command == "STATUS") {
    reportStatus();
  } else if (command.length() > 0) {
    Serial.print("❌ Unknown command: '");
    Serial.print(command);
    Serial.println("'");
  }

  Serial.flush();
}

void triggerRansomwareAlert() {
  Serial.println("🚨 RANSOMWARE DETECTED! Activating alert system...");
  stopAllAlerts();

  isRansomwareAlert = true;
  alertStartTime = millis();
  buzzerBeepCount = 0;

  digitalWrite(RED_LED_PIN, HIGH);
  digitalWrite(BUZZER_PIN, HIGH);
  buzzerState = true;
  lastBuzzerTime = millis();

  Serial.println("✓ Red LED ON, Buzzer ACTIVE");
  Serial.flush();
}

void triggerBenignAlert() {
  Serial.println("✅ Benign file detected - Safe");
  stopAllAlerts();

  // Flash green LED twice with soft beeps
  for (int i = 0; i < 2; i++) {
    digitalWrite(GREEN_LED_PIN, HIGH);
    digitalWrite(BUZZER_PIN, HIGH);
    delay(200);
    digitalWrite(GREEN_LED_PIN, LOW);
    digitalWrite(BUZZER_PIN, LOW);
    delay(200);
  }

  Serial.println("✓ Green LED blinked twice with soft beeps");
  Serial.flush();
}

void runSystemTest() {
  Serial.println("🔧 Running system test...");
  Serial.flush();
  stopAllAlerts();

  // Test Red LED
  Serial.println("Testing Red LED...");
  digitalWrite(RED_LED_PIN, HIGH);
  delay(500);
  digitalWrite(RED_LED_PIN, LOW);
  delay(200);

  // Test Green LED + Beep (benign simulation)
  Serial.println("Testing Green LED + soft beep...");
  for (int i = 0; i < 2; i++) {
    digitalWrite(GREEN_LED_PIN, HIGH);
    digitalWrite(BUZZER_PIN, HIGH);
    delay(200);
    digitalWrite(GREEN_LED_PIN, LOW);
    digitalWrite(BUZZER_PIN, LOW);
    delay(200);
  }

  // Test all together
  Serial.println("Testing all components together...");
  digitalWrite(RED_LED_PIN, HIGH);
  digitalWrite(GREEN_LED_PIN, HIGH);
  digitalWrite(BUZZER_PIN, HIGH);
  delay(300);
  digitalWrite(RED_LED_PIN, LOW);
  digitalWrite(GREEN_LED_PIN, LOW);
  digitalWrite(BUZZER_PIN, LOW);

  Serial.println("✅ System test completed successfully!");
  Serial.flush();
}

void updateAlerts() {
  unsigned long currentTime = millis();

  if (isRansomwareAlert) {
    if (currentTime - alertStartTime >= RANSOMWARE_ALERT_DURATION) {
      stopRansomwareAlert();
      return;
    }

    if (buzzerBeepCount < MAX_BUZZER_BEEPS) {
      if (buzzerState && (currentTime - lastBuzzerTime >= BUZZER_BEEP_DURATION)) {
        digitalWrite(BUZZER_PIN, LOW);
        buzzerState = false;
        lastBuzzerTime = currentTime;
      } else if (!buzzerState && (currentTime - lastBuzzerTime >= BUZZER_PAUSE_DURATION)) {
        digitalWrite(BUZZER_PIN, HIGH);
        buzzerState = true;
        lastBuzzerTime = currentTime;
        buzzerBeepCount++;
      }
    } else {
      digitalWrite(BUZZER_PIN, LOW);
      buzzerState = false;
    }
  }
}

void stopRansomwareAlert() {
  Serial.println("Ransomware alert completed");
  isRansomwareAlert = false;
  digitalWrite(RED_LED_PIN, LOW);
  digitalWrite(BUZZER_PIN, LOW);
  buzzerState = false;
  buzzerBeepCount = 0;
  Serial.flush();
}

void stopAllAlerts() {
  Serial.println("Stopping all alerts");
  isRansomwareAlert = false;

  digitalWrite(RED_LED_PIN, LOW);
  digitalWrite(GREEN_LED_PIN, LOW);
  digitalWrite(BUZZER_PIN, LOW);

  buzzerState = false;
  buzzerBeepCount = 0;
  Serial.flush();
}

void reportStatus() {
  Serial.println("=== SYSTEM STATUS ===");
  Serial.print("Red LED (Pin 8): ");
  Serial.println(digitalRead(RED_LED_PIN) ? "ON" : "OFF");
  Serial.print("Green LED (Pin 3): ");
  Serial.println(digitalRead(GREEN_LED_PIN) ? "ON" : "OFF");
  Serial.print("Buzzer (Pin 13): ");
  Serial.println(digitalRead(BUZZER_PIN) ? "ON" : "OFF");
  Serial.print("Ransomware Alert Active: ");
  Serial.println(isRansomwareAlert ? "YES" : "NO");
  Serial.println("====================");
  Serial.flush();
}

void startupSequence() {
  digitalWrite(GREEN_LED_PIN, HIGH);
  delay(200);
  digitalWrite(GREEN_LED_PIN, LOW);
  delay(100);

  digitalWrite(BUZZER_PIN, HIGH);
  delay(100);
  digitalWrite(BUZZER_PIN, LOW);
}
