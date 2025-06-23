/*
 * Ransomware Detection System - Arduino Controller
 * Compatible with Python Streamlit Detection System
 * 
 * Features:
 * - Serial command processing with buffer management
 * - Non-blocking LED and buzzer control
 * - Themed sound patterns for detection results
 * - Automatic timeout and cleanup
 * - Built-in testing mode
 * - Memory-efficient operation
 */

// Pin Definitions
const int GREEN_LED_PIN = 3;    // Benign detection indicator
const int RED_LED_PIN = 8;      // Malicious detection indicator
const int BUZZER_PIN = 13;      // Audio alert system

// Timing Constants
const unsigned long LED_DURATION = 3000;        // LED display time (3 seconds)
const unsigned long SERIAL_TIMEOUT = 100;       // Serial read timeout
const unsigned long HEARTBEAT_INTERVAL = 30000; // Heartbeat every 30 seconds

// Sound Patterns (frequencies in Hz, durations in ms)
// Benign Sound: Gentle ascending chime sequence
const int BENIGN_NOTES[] = {523, 659, 784, 1047}; // C5, E5, G5, C6
const int BENIGN_DURATIONS[] = {150, 150, 150, 300};
const int BENIGN_NOTE_COUNT = 4;

// Malicious Sound: Urgent warning sequence
const int MALICIOUS_NOTES[] = {220, 0, 220, 0, 330, 0, 220, 0, 220}; // A3 with pauses, then E4
const int MALICIOUS_DURATIONS[] = {200, 100, 200, 100, 400, 200, 200, 100, 400};
const int MALICIOUS_NOTE_COUNT = 9;

// System State Variables
struct SystemState {
  bool greenLedActive = false;
  bool redLedActive = false;
  bool soundPlaying = false;
  unsigned long ledStartTime = 0;
  unsigned long lastHeartbeat = 0;
  int currentNote = 0;
  unsigned long noteStartTime = 0;
  bool isBenignSequence = false;
  String inputBuffer = "";
  unsigned long lastActivity = 0;
  bool connectionEstablished = false;
} state;

// System Statistics
struct Statistics {
  unsigned long benignCount = 0;
  unsigned long maliciousCount = 0;
  unsigned long totalCommands = 0;
  unsigned long systemUptime = 0;
  unsigned long lastResetTime = 0;
} stats;

void setup() {
  // Initialize serial communication
  Serial.begin(9600);
  Serial.setTimeout(SERIAL_TIMEOUT);
  
  // Configure pins
  pinMode(GREEN_LED_PIN, OUTPUT);
  pinMode(RED_LED_PIN, OUTPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  
  // Initialize all outputs to OFF
  digitalWrite(GREEN_LED_PIN, LOW);
  digitalWrite(RED_LED_PIN, LOW);
  digitalWrite(BUZZER_PIN, LOW);
  
  // Startup sequence
  performStartupSequence();
  
  // Initialize timestamps
  state.lastHeartbeat = millis();
  stats.lastResetTime = millis();
  
  Serial.println("RANSOMWARE_DETECTOR_READY");
  Serial.println("Commands: BENIGN, RANSOMWARE, TEST, STATUS, RESET");
  Serial.println("Waiting for connection...");
}

void loop() {
  unsigned long currentTime = millis();
  
  // Handle serial communication
  handleSerialInput();
  
  // Update LED states
  updateLEDs(currentTime);
  
  // Handle sound playback
  updateSoundPlayback(currentTime);
  
  // Send periodic heartbeat
  sendHeartbeat(currentTime);
  
  // Update system uptime
  stats.systemUptime = currentTime - stats.lastResetTime;
  
  // Small delay to prevent overwhelming the system
  delay(10);
}

void handleSerialInput() {
  if (Serial.available() > 0) {
    char incomingByte = Serial.read();
    
    // Handle complete lines
    if (incomingByte == '\n' || incomingByte == '\r') {
      if (state.inputBuffer.length() > 0) {
        processCommand(state.inputBuffer);
        state.inputBuffer = "";
      }
    }
    // Buffer management - prevent overflow
    else if (state.inputBuffer.length() < 50) {
      state.inputBuffer += incomingByte;
    }
    else {
      // Buffer overflow protection
      state.inputBuffer = "";
      Serial.println("ERROR: Command too long");
    }
    
    state.lastActivity = millis();
  }
}

void processCommand(String command) {
  command.trim();
  command.toUpperCase();
  
  stats.totalCommands++;
  
  Serial.print("RECEIVED: ");
  Serial.println(command);
  
  // Establish connection on first command
  if (!state.connectionEstablished) {
    state.connectionEstablished = true;
    Serial.println("CONNECTION_ESTABLISHED");
    performConnectionTest();
  }
  
  if (command == "BENIGN") {
    handleBenignDetection();
  }
  else if (command == "RANSOMWARE" || command == "MALICIOUS") {
    handleMaliciousDetection();
  }
  else if (command == "TEST") {
    performSystemTest();
  }
  else if (command == "STATUS") {
    sendSystemStatus();
  }
  else if (command == "RESET") {
    resetSystem();
  }
  else if (command == "STOP") {
    stopAllAlerts();
  }
  else {
    Serial.print("ERROR: Unknown command - ");
    Serial.println(command);
  }
}

void handleBenignDetection() {
  stopAllAlerts(); // Stop any current activity
  
  state.greenLedActive = true;
  state.redLedActive = false;
  state.ledStartTime = millis();
  
  startBenignSound();
  stats.benignCount++;
  
  Serial.println("STATUS: BENIGN_DETECTED");
}

void handleMaliciousDetection() {
  stopAllAlerts(); // Stop any current activity
  
  state.redLedActive = true;
  state.greenLedActive = false;
  state.ledStartTime = millis();
  
  startMaliciousSound();
  stats.maliciousCount++;
  
  Serial.println("STATUS: MALICIOUS_DETECTED");
}

void startBenignSound() {
  state.soundPlaying = true;
  state.isBenignSequence = true;
  state.currentNote = 0;
  state.noteStartTime = millis();
}

void startMaliciousSound() {
  state.soundPlaying = true;
  state.isBenignSequence = false;
  state.currentNote = 0;
  state.noteStartTime = millis();
}

void updateLEDs(unsigned long currentTime) {
  // Handle LED timeouts
  if ((state.greenLedActive || state.redLedActive) && 
      (currentTime - state.ledStartTime >= LED_DURATION)) {
    state.greenLedActive = false;
    state.redLedActive = false;
  }
  
  // Update LED states
  digitalWrite(GREEN_LED_PIN, state.greenLedActive ? HIGH : LOW);
  digitalWrite(RED_LED_PIN, state.redLedActive ? HIGH : LOW);
}

void updateSoundPlayback(unsigned long currentTime) {
  if (!state.soundPlaying) {
    digitalWrite(BUZZER_PIN, LOW);
    return;
  }
  
  const int* notes;
  const int* durations;
  int noteCount;
  
  // Select appropriate sound sequence
  if (state.isBenignSequence) {
    notes = BENIGN_NOTES;
    durations = BENIGN_DURATIONS;
    noteCount = BENIGN_NOTE_COUNT;
  } else {
    notes = MALICIOUS_NOTES;
    durations = MALICIOUS_DURATIONS;
    noteCount = MALICIOUS_NOTE_COUNT;
  }
  
  // Check if current note should end
  if (currentTime - state.noteStartTime >= durations[state.currentNote]) {
    state.currentNote++;
    
    // Check if sequence is complete
    if (state.currentNote >= noteCount) {
      state.soundPlaying = false;
      digitalWrite(BUZZER_PIN, LOW);
      return;
    }
    
    state.noteStartTime = currentTime;
  }
  
  // Play current note
  int currentFreq = notes[state.currentNote];
  if (currentFreq > 0) {
    tone(BUZZER_PIN, currentFreq);
  } else {
    digitalWrite(BUZZER_PIN, LOW); // Rest/pause
  }
}

void performConnectionTest() {
  Serial.println("STATUS: CONNECTION_TEST_START");
  
  // Quick test sequence to confirm hardware after connection
  stopAllAlerts();
  
  // Green LED test
  digitalWrite(GREEN_LED_PIN, HIGH);
  delay(300);
  digitalWrite(GREEN_LED_PIN, LOW);
  delay(100);
  
  // Red LED test  
  digitalWrite(RED_LED_PIN, HIGH);
  delay(300);
  digitalWrite(RED_LED_PIN, LOW);
  delay(100);
  
  // Quick beep confirmation
  tone(BUZZER_PIN, 1000, 200);
  delay(250);
  
  Serial.println("STATUS: CONNECTION_TEST_COMPLETE");
  Serial.println("System ready for ransomware detection!");
}

void performSystemTest() {
  Serial.println("STATUS: SYSTEM_TEST_START");
  
  // Test sequence: Green -> Red -> Sound test
  stopAllAlerts();
  
  // Test green LED
  digitalWrite(GREEN_LED_PIN, HIGH);
  delay(500);
  digitalWrite(GREEN_LED_PIN, LOW);
  delay(200);
  
  // Test red LED
  digitalWrite(RED_LED_PIN, HIGH);
  delay(500);
  digitalWrite(RED_LED_PIN, LOW);
  delay(200);
  
  // Test benign sound
  startBenignSound();
  delay(1000); // Let it play for a bit
  
  // Test malicious sound
  startMaliciousSound();
  delay(1500); // Let it play for a bit
  
  stopAllAlerts();
  Serial.println("STATUS: SYSTEM_TEST_COMPLETE");
}

void performStartupSequence() {
  Serial.println("STATUS: STARTUP_SEQUENCE");
  
  // LED sweep
  digitalWrite(GREEN_LED_PIN, HIGH);
  delay(300);
  digitalWrite(RED_LED_PIN, HIGH);
  delay(300);
  digitalWrite(GREEN_LED_PIN, LOW);
  delay(300);
  digitalWrite(RED_LED_PIN, LOW);
  
  // Startup chime
  tone(BUZZER_PIN, 523, 150); // C5
  delay(200);
  tone(BUZZER_PIN, 659, 150); // E5
  delay(200);
  tone(BUZZER_PIN, 784, 300); // G5
  delay(350);
  
  digitalWrite(BUZZER_PIN, LOW);
}

void sendHeartbeat(unsigned long currentTime) {
  if (currentTime - state.lastHeartbeat >= HEARTBEAT_INTERVAL) {
    Serial.println("HEARTBEAT");
    state.lastHeartbeat = currentTime;
  }
}

void sendSystemStatus() {
  Serial.println("=== SYSTEM STATUS ===");
  Serial.print("Connection: ");
  Serial.println(state.connectionEstablished ? "ESTABLISHED" : "WAITING");
  Serial.print("Uptime: ");
  Serial.print(stats.systemUptime / 1000);
  Serial.println(" seconds");
  Serial.print("Total Commands: ");
  Serial.println(stats.totalCommands);
  Serial.print("Benign Detections: ");
  Serial.println(stats.benignCount);
  Serial.print("Malicious Detections: ");
  Serial.println(stats.maliciousCount);
  Serial.print("Green LED: ");
  Serial.println(state.greenLedActive ? "ON" : "OFF");
  Serial.print("Red LED: ");
  Serial.println(state.redLedActive ? "ON" : "OFF");
  Serial.print("Sound Playing: ");
  Serial.println(state.soundPlaying ? "YES" : "NO");
  Serial.print("Last Activity: ");
  Serial.print((millis() - state.lastActivity) / 1000);
  Serial.println(" seconds ago");
  Serial.println("===================");
}

void resetSystem() {
  Serial.println("STATUS: SYSTEM_RESET");
  
  // Reset all states
  stopAllAlerts();
  
  // Reset connection state
  state.connectionEstablished = false;
  
  // Reset statistics
  stats.benignCount = 0;
  stats.maliciousCount = 0;
  stats.totalCommands = 0;
  stats.lastResetTime = millis();
  
  // Clear input buffer
  state.inputBuffer = "";
  state.lastActivity = millis();
  
  // Confirmation sequence
  for (int i = 0; i < 3; i++) {
    digitalWrite(GREEN_LED_PIN, HIGH);
    digitalWrite(RED_LED_PIN, HIGH);
    tone(BUZZER_PIN, 440, 100);
    delay(150);
    digitalWrite(GREEN_LED_PIN, LOW);
    digitalWrite(RED_LED_PIN, LOW);
    digitalWrite(BUZZER_PIN, LOW);
    delay(150);
  }
  
  Serial.println("STATUS: RESET_COMPLETE");
  Serial.println("Waiting for connection...");
}

void stopAllAlerts() {
  state.greenLedActive = false;
  state.redLedActive = false;
  state.soundPlaying = false;
  
  digitalWrite(GREEN_LED_PIN, LOW);
  digitalWrite(RED_LED_PIN, LOW);
  digitalWrite(BUZZER_PIN, LOW);
}