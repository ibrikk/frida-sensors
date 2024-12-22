// Main Frida script
setTimeout(() => {
  Java.perform(() => {
    console.log("Frida script started.");

    const ActivityThread = Java.use("android.app.ActivityThread");
    const currentApplication = ActivityThread.currentApplication();
    const context = currentApplication.getApplicationContext();

    const SensorManager = Java.use("android.hardware.SensorManager");
    const sensorManager = Java.cast(
      context.getSystemService("sensor"),
      SensorManager
    );

    const Sensor = Java.use("android.hardware.Sensor");
    const SENSOR_TYPE_ACCELEROMETER = Sensor.TYPE_ACCELEROMETER.value;
    const SENSOR_TYPE_GYROSCOPE = Sensor.TYPE_GYROSCOPE.value;
    const SENSOR_TYPE_LINEAR_ACCELERATION =
      Sensor.TYPE_LINEAR_ACCELERATION.value;
    const SENSOR_TYPE_ORIENTATION = Sensor.TYPE_ORIENTATION.value;
    const SENSOR_TYPE_LIGHT = Sensor.TYPE_LIGHT.value;
    const SENSOR_TYPE_PRESSURE = Sensor.TYPE_PRESSURE.value;
    const SENSOR_TYPE_PROXIMITY = Sensor.TYPE_PROXIMITY.value;
    const SENSOR_TYPE_GRAVITY = Sensor.TYPE_GRAVITY.value;
    const SENSOR_TYPE_ROTATION_VECTOR = Sensor.TYPE_ROTATION_VECTOR.value;
    const SENSOR_TYPE_STEP_COUNTER = Sensor.TYPE_STEP_COUNTER.value;
    const SENSOR_TYPE_MAGNETIC_FIELD = Sensor.TYPE_MAGNETIC_FIELD.value;

    const accelerometerSensor = sensorManager.getDefaultSensor(
      SENSOR_TYPE_ACCELEROMETER
    );
    const gyroscopeSensor = sensorManager.getDefaultSensor(
      SENSOR_TYPE_GYROSCOPE
    );
    const linearAccelerometerSensor = sensorManager.getDefaultSensor(
      SENSOR_TYPE_LINEAR_ACCELERATION
    );
    const orientationSensor = sensorManager.getDefaultSensor(
      SENSOR_TYPE_ORIENTATION
    );
    const lightSensor = sensorManager.getDefaultSensor(SENSOR_TYPE_LIGHT);
    const pressureSensor = sensorManager.getDefaultSensor(SENSOR_TYPE_PRESSURE);
    const proximitySensor = sensorManager.getDefaultSensor(
      SENSOR_TYPE_PROXIMITY
    );
    const gravitySensor = sensorManager.getDefaultSensor(SENSOR_TYPE_GRAVITY);
    const rotationVectorSensor = sensorManager.getDefaultSensor(
      SENSOR_TYPE_ROTATION_VECTOR
    );
    const stepCounterSensor = sensorManager.getDefaultSensor(
      SENSOR_TYPE_STEP_COUNTER
    );
    const geomagneticFieldSensor = sensorManager.getDefaultSensor(
      SENSOR_TYPE_MAGNETIC_FIELD
    );

    const SystemSensorManager = Java.use(
      "android.hardware.SystemSensorManager"
    );
    const SensorEventQueue = Java.use(
      "android.hardware.SystemSensorManager$SensorEventQueue"
    );

    const BatteryManager = Java.use("android.os.BatteryManager");
    BatteryManager.getIntProperty.implementation = function (id: number) {
      const batteryInfo = simulateBattery();
      if (id === BatteryManager.BATTERY_PROPERTY_CAPACITY) {
        return parseInt(batteryInfo.level, 10);
      }
      return this.getIntProperty(id);
    };
    BatteryManager.isCharging.implementation = function () {
      const batteryInfo = simulateBattery();
      console.log(
        `[BatteryManager] Returning spoofed charging status: ${batteryInfo.charging}`
      );
      return batteryInfo.charging;
    };

    let spoofingActivity = "sedentary";

    SensorEventQueue.dispatchSensorEvent.implementation = function (
      handle: number,
      values: number[],
      accuracy: number,
      timestamp: number
    ) {
      let spoofedValues;

      if (
        accelerometerSensor !== null &&
        handle === accelerometerSensor.getHandle()
      ) {
        spoofedValues = simulateActivity(spoofingActivity, false);
        // values[0] = spoofedValues[0];
        // values[1] = spoofedValues[1];
        // values[2] = spoofedValues[2];
        values[0] = 5;
        values[1] = 5;
        values[2] = 5;
        console.log(`[Accelerometer] ${spoofingActivity}: ${values}`);
      }

      if (gyroscopeSensor !== null && handle === gyroscopeSensor.getHandle()) {
        spoofedValues = simulateActivity(spoofingActivity, false);
        // values[0] = spoofedValues[0];
        // values[1] = spoofedValues[1];
        // values[2] = spoofedValues[2];
        values[0] = 5;
        values[1] = 5;
        values[2] = 5;
        console.log(`[Gyroscope] ${spoofingActivity}: ${values}`);
      }

      if (
        linearAccelerometerSensor !== null &&
        handle === linearAccelerometerSensor.getHandle()
      ) {
        spoofedValues = simulateLinearAcceleration(spoofingActivity);
        // values[0] = spoofedValues[0];
        // values[1] = spoofedValues[1];
        // values[2] = spoofedValues[2];
        values[0] = 5;
        values[1] = 5;
        values[2] = 5;
        console.log(`[Linear Accelerometer]: ${values}`);
      }

      if (
        geomagneticFieldSensor !== null &&
        handle === geomagneticFieldSensor.getHandle()
      ) {
        spoofedValues = simulateGeomagneticField();
        // values[0] = spoofedValues[0];
        // values[1] = spoofedValues[1];
        // values[2] = spoofedValues[2];
        values[0] = 5;
        values[1] = 5;
        values[2] = 5;
        console.log(`[Geomagnetic Field]: ${values}`);
      }

      if (lightSensor !== null && handle === lightSensor.getHandle()) {
        // values[0] = simulateLight();
        values[0] = 500;
        console.log(`[Light]: ${values[0]} Lux`);
      }

      if (pressureSensor !== null && handle === pressureSensor.getHandle()) {
        // values[0] = simulatePressure();
        values[0] = 5;
        console.log(`[Pressure]: ${values[0]} hPa`);
      }

      if (proximitySensor !== null && handle === proximitySensor.getHandle()) {
        // values[0] = simulateProximity();
        values[0] = 5;
        console.log(`[Proximity]: ${values[0]} cm`);
      }

      if (
        stepCounterSensor !== null &&
        handle === stepCounterSensor.getHandle()
      ) {
        // values[0] = simulateStepCounter();
        values[0] = 5;
        console.log(`[Step Counter]: ${values[0]} steps`);
      }

      if (gravitySensor !== null && handle === gravitySensor.getHandle()) {
        spoofedValues = simulateGravity();
        // values[0] = spoofedValues[0];
        // values[1] = spoofedValues[1];
        // values[2] = spoofedValues[2];
        values[0] = 5;
        values[1] = 5;
        values[2] = 5;
        console.log(`[Gravity]: ${values}`);
      }

      if (
        rotationVectorSensor !== null &&
        handle === rotationVectorSensor.getHandle()
      ) {
        spoofedValues = simulateRotationVector();
        // values[0] = spoofedValues[0];
        // values[1] = spoofedValues[1];
        // values[2] = spoofedValues[2];
        values[0] = 5;
        values[1] = 5;
        values[2] = 5;
        console.log(`[Rotation Vector]: ${values}`);
      }

      if (
        orientationSensor !== null &&
        handle === orientationSensor.getHandle()
      ) {
        spoofedValues = simulateOrientation();
        // values[0] = spoofedValues[0];
        // values[1] = spoofedValues[1];
        // values[2] = spoofedValues[2];
        values[0] = 5;
        values[1] = 5;
        values[2] = 5;
        console.log(`[Orientation]: ${values}`);
      }

      console.log(`[Battery]:`, simulateBattery());
      console.log(`[System Info]:`, simulateSystemInfo());
      console.log(`[Microphone]: ${simulateMicrophone()}`);
      console.log(`[Camera]:`, simulateCameraStatus());

      return this.dispatchSensorEvent(handle, values, accuracy, timestamp);
    };

    // // Hook Build class to spoof system information
    // const Build = Java.use("android.os.Build");
    // Build.MODEL.value = simulateSystemInfo().model;
    // Build.MANUFACTURER.value = simulateSystemInfo().manufacturer;
    // Build.VERSION.RELEASE.value = simulateSystemInfo().androidVersion;

    // Hook Runtime class to spoof available processors (for RAM simulation)
    // const Runtime = Java.use("java.lang.Runtime");
    // Runtime.availableProcessors.implementation = function () {
    //   const ramInfo = simulateSystemInfo().ram;
    //   const processors = parseInt(ramInfo.split(" ")[0], 10);
    //   console.log(
    //     `[Runtime] Returning spoofed available processors: ${processors}`
    //   );
    //   return processors;
    // };

    // Hook Camera class to spoof camera status
    // const Camera = Java.use("android.hardware.Camera");
    // Camera.open.implementation = function (cameraId: number) {
    //   const cameraStatus = simulateCameraStatus();
    //   if (cameraId === 0 && cameraStatus.frontCamera === "inactive") {
    //     throw new Error("Front camera is inactive");
    //   } else if (cameraId === 1 && cameraStatus.backCamera === "inactive") {
    //     throw new Error("Back camera is inactive");
    //   }
    //   console.log(`[Camera] Opening camera with ID: ${cameraId}`);
    //   return this.open(cameraId);
    // };

    // Hook AudioRecord class to spoof microphone status
    // const AudioRecord = Java.use("android.media.AudioRecord");
    // AudioRecord.startRecording.implementation = function () {
    //   const micStatus = simulateMicrophone();
    //   if (micStatus === "inactive") {
    //     throw new Error("Microphone is inactive");
    //   }
    //   console.log("[AudioRecord] Starting recording");
    //   this.startRecording();
    // };

    console.log("Frida script setup complete.");
  });
}, 10);

/* UTILITY FUNCTIONS */
const randomRange = (min: number, max: number) =>
  Math.random() * (max - min) + min;
const generateDrift = (base: number, variance: number) =>
  base + randomRange(-variance, variance);

// Simulate various sensors
const simulateActivity = (activityType: string, isLinear = false) => {
  switch (activityType) {
    case "sedentary":
      return [
        generateDrift(0, 0.2),
        generateDrift(0, 0.2),
        isLinear ? generateDrift(0, 0.2) : generateDrift(9.8, 0.1),
      ];
    case "running":
      return [
        generateDrift(0, 5.0),
        generateDrift(0, 5.0),
        generateDrift(9.8, 2.0),
      ];
    case "driving":
      return [
        generateDrift(0, 2.0),
        generateDrift(0, 2.0),
        isLinear ? generateDrift(0, 1.0) : generateDrift(9.8, 0.5),
      ];
    default:
      return [0, 0, 0];
  }
};
const simulateStepCounter = (() => {
  let steps = 0;
  return () => {
    steps += Math.floor(randomRange(1, 3)); // Increment steps gradually
    return steps;
  };
})();
const simulateBattery = (() => {
  let level = 100;
  return () => {
    level = Math.max(0, level - randomRange(0.05, 0.1)); // Decrease slowly
    return { level: level.toFixed(1), charging: Math.random() < 0.5 };
  };
})();
const simulateOrientation = () => [
  generateDrift(0, 180),
  generateDrift(0, 90),
  generateDrift(0, 180),
];
const simulateGeomagneticField = () => [
  generateDrift(25, 5), // X-axis
  generateDrift(25, 5), // Y-axis
  generateDrift(50, 5), // Z-axis
];
const simulateLight = () => generateDrift(500, 50);
const simulatePressure = () => generateDrift(1013, 5);
const simulateProximity = () => generateDrift(0, 5);
const simulateRotationVector = () => [
  generateDrift(0, 1),
  generateDrift(0, 1),
  generateDrift(0, 1),
];
const simulateLinearAcceleration = (activityType: string) =>
  simulateActivity(activityType, true);
const simulateGravity = () => [0.0, 0.0, 9.8];

// Simulate system information
const simulateSystemInfo = () => ({
  time: new Date().toISOString(),
  model: "Pixel 69 Pro",
  manufacturer: "Google",
  androidVersion: "13",
  ram: `${generateDrift(6, 1).toFixed(1)} GB`,
  storage: `${generateDrift(128, 10).toFixed(0)} GB`,
});

// Simulate microphone and cameras
const simulateMicrophone = () => (Math.random() < 0.5 ? "active" : "inactive");
const simulateCameraStatus = () => ({
  frontCamera: Math.random() < 0.5 ? "active" : "inactive",
  backCamera: Math.random() < 0.5 ? "active" : "inactive",
});
