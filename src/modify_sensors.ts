// Utility function to generate random numbers within a range
const randomRange = (min: number, max: number) => {
  return Math.random() * (max - min) + min;
};

// Function to simulate different activities
const simulateActivity = (activityType: string, isLinear: boolean = false) => {
  let values = [0.0, 0.0, 0.0]; // Default sensor values

  switch (activityType) {
    case "sedentary":
      // Small random fluctuations to simulate minimal movement
      values = [
        randomRange(-0.2, 0.2), // X-axis
        randomRange(-0.2, 0.2), // Y-axis
        isLinear ? randomRange(-0.2, 0.2) : randomRange(9.8, 9.9), // Z-axis
      ];
      break;

    case "running":
      // Larger fluctuations to simulate running
      values = [
        randomRange(-5.0, 5.0), // X-axis
        randomRange(-5.0, 5.0), // Y-axis
        randomRange(7.0, 12.0), // Z-axis (jumping and impact)
      ];
      break;

    case "driving":
      // Moderate fluctuations to simulate driving
      values = [
        randomRange(-2.0, 2.0), // X-axis
        randomRange(-2.0, 2.0), // Y-axis
        isLinear ? randomRange(-1.0, 1.0) : randomRange(8.0, 10.0), // Z-axis
      ];
      break;

    default:
      console.error("Unknown activity type:", activityType);
  }

  return values;
};

// Frida script logic
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

    const accelerometerSensor = sensorManager.getDefaultSensor(
      SENSOR_TYPE_ACCELEROMETER
    );
    const gyroscopeSensor = sensorManager.getDefaultSensor(
      SENSOR_TYPE_GYROSCOPE
    );
    const linearAccelerometerSensor = sensorManager.getDefaultSensor(
      SENSOR_TYPE_LINEAR_ACCELERATION
    );

    const SystemSensorManager = Java.use(
      "android.hardware.SystemSensorManager"
    );
    const SensorEventQueue = Java.use(
      "android.hardware.SystemSensorManager$SensorEventQueue"
    );

    // Variable to control the spoofing type
    let spoofingActivity = "sedentary"; // Options: sedentary, running, driving

    SensorEventQueue.dispatchSensorEvent.implementation = function (
      handle: number,
      values: number[],
      accuracy: number,
      timestamp: number
    ) {
      let spoofedValues: number[];

      // Handle Accelerometer
      if (
        accelerometerSensor !== null &&
        handle === accelerometerSensor.getHandle()
      ) {
        spoofedValues = simulateActivity(spoofingActivity, false); // false: include gravity
        values[0] = spoofedValues[0]; // X-axis
        values[1] = spoofedValues[1]; // Y-axis
        values[2] = spoofedValues[2]; // Z-axis
        console.log(
          `[Accelerometer] Activity: ${spoofingActivity}, Values: ${values}`
        );
      }

      // Handle Gyroscope
      if (gyroscopeSensor !== null && handle === gyroscopeSensor.getHandle()) {
        spoofedValues = simulateActivity(spoofingActivity, false);
        values[0] = spoofedValues[0]; // X-axis
        values[1] = spoofedValues[1]; // Y-axis
        values[2] = spoofedValues[2]; // Z-axis
        console.log(
          `[Gyroscope] Activity: ${spoofingActivity}, Values: ${values}`
        );
      }

      // Handle Linear Accelerometer
      if (
        linearAccelerometerSensor !== null &&
        handle === linearAccelerometerSensor.getHandle()
      ) {
        spoofedValues = simulateActivity(spoofingActivity, true); // true: exclude gravity
        values[0] = spoofedValues[0]; // X-axis
        values[1] = spoofedValues[1]; // Y-axis
        values[2] = spoofedValues[2]; // Z-axis
        console.log(
          `[Linear Accelerometer] Activity: ${spoofingActivity}, Values: ${values}`
        );
      }

      // Call the original method with the (possibly) modified values
      return this.dispatchSensorEvent(handle, values, accuracy, timestamp);
    };

    console.log("Frida script setup complete. Default activity: sedentary");

    // Dynamically change activity type
    setTimeout(() => {
      spoofingActivity = "running";
      console.log("Switched to running activity.");
    }, 30000); // Switch to running after 30 seconds

    setTimeout(() => {
      spoofingActivity = "driving";
      console.log("Switched to driving activity.");
    }, 60000); // Switch to driving after 60 seconds
  });
}, 10);
