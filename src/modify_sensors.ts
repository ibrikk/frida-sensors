Java.perform(() => {
  console.log("Frida script started.");

  // Access the ActivityThread class to get the current application context
  const ActivityThread = Java.use("android.app.ActivityThread");
  const currentApplication = ActivityThread.currentApplication();
  if (currentApplication === null) {
    console.error("Failed to retrieve current application.");
    // return;
  }
  const context = currentApplication.getApplicationContext();
  if (context === null) {
    console.error("Failed to retrieve application context.");
    return;
  }
  console.log("Application context retrieved successfully.");

  // Access the SensorManager system service
  const SensorManager = Java.use("android.hardware.SensorManager");
  const sensorManager = Java.cast(
    context.getSystemService("sensor"),
    SensorManager
  );
  if (sensorManager === null) {
    console.error("Failed to retrieve SensorManager.");
    return;
  }
  console.log("SensorManager retrieved successfully.");

  // Access the Sensor class and define the accelerometer sensor type
  const Sensor = Java.use("android.hardware.Sensor");
  const SENSOR_TYPE_ACCELEROMETER = Sensor.TYPE_ACCELEROMETER.value;
  const SENSOR_TYPE_GYROSCOPE = Sensor.TYPE_GYROSCOPE.value;
  console.log(
    `Gyroscope sensor type: ${SENSOR_TYPE_GYROSCOPE}, Accelerometer sensor type: ${SENSOR_TYPE_ACCELEROMETER}`
  );

  // Retrieve the default accelerometer sensor
  const accelerometerSensor = sensorManager.getDefaultSensor(
    SENSOR_TYPE_ACCELEROMETER
  );
  const gyroscopeSensor = sensorManager.getDefaultSensor(SENSOR_TYPE_GYROSCOPE);
  if (accelerometerSensor === null) {
    console.error("Accelerometer sensor not found.");
  } else {
    console.log("Accelerometer sensor retrieved successfully.");
  }

  if (gyroscopeSensor === null) {
    console.error("Gyroscope sensor not found.");
  } else {
    console.log("Gyroscope sensor retrieved successfully.");
  }

  // Access the internal SensorEventQueue class
  const SystemSensorManager = Java.use("android.hardware.SystemSensorManager");
  const SensorEventQueue = Java.use(
    "android.hardware.SystemSensorManager$SensorEventQueue"
  );
  if (SensorEventQueue === null) {
    console.error("Failed to access SensorEventQueue class.");
    return;
  }
  console.log("SensorEventQueue class accessed successfully.");

  // Hook the dispatchSensorEvent method to intercept sensor data
  SensorEventQueue.dispatchSensorEvent.implementation = function (
    handle: number,
    values: number[],
    accuracy: number,
    timestamp: number
  ) {
    console.log(
      `dispatchSensorEvent called with handle: ${handle}, values: ${values}, accuracy: ${accuracy}, timestamp: ${timestamp}`
    );

    // Check if the event is from the accelerometer sensor
    if (
      accelerometerSensor !== null &&
      handle === accelerometerSensor.getHandle()
    ) {
      // Modify the accelerometer values
      values[0] = 5.0; // X-axis
      values[1] = 5.0; // Y-axis
      values[2] = 5.0; // Z-axis
      console.log("Accelerometer data modified:", values);
    }

    // Check if the event is from the gyroscope or accelerometer sensor
    if (gyroscopeSensor !== null && handle === gyroscopeSensor.getHandle()) {
      // Modify gyroscope values
      values[0] = 7.0; // X-axis
      values[1] = 7.0; // Y-axis
      values[2] = 7.0; // Z-axis
      console.log("Gyroscope data modified:", values);
    }

    // Call the original method with the (possibly) modified values
    return this.dispatchSensorEvent(handle, values, accuracy, timestamp);
  };

  console.log("Frida script setup complete.");
});
interface IActivityThread {
  currentApplication(): any;
}

interface IContext {
  getApplicationContext(): any;
  getSystemService(name: string): any;
}

interface ISensorManager {
  getDefaultSensor(type: number): any;
}

interface ISensor {
  TYPE_ACCELEROMETER: any;
  getHandle(): any;
}

interface ISensorEventQueue {
  dispatchSensorEvent(
    handle: number,
    values: number[],
    accuracy: number,
    timestamp: number
  ): void;
}

// const ActivityThread: IActivityThread = Java.use("android.app.ActivityThread");
// const SensorManager: ISensorManager = Java.use(
//   "android.hardware.SensorManager"
// );
// const Sensor: ISensor = Java.use("android.hardware.Sensor");
// const SystemSensorManager = Java.use("android.hardware.SystemSensorManager");
// const SensorEventQueue: ISensorEventQueue = Java.use(
//   "android.hardware.SystemSensorManager$SensorEventQueue"
// );
