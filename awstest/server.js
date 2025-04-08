const express = require('express');
const cors = require('cors');
const { EC2Client, DescribeInstancesCommand } = require("@aws-sdk/client-ec2");

const app = express();
app.use(cors());

// Simple health check
app.get('/', (req, res) => {
  res.send('✅ Server is alive');
});



// ✅ Directly defined AWS credentials
const AWS_ACCESS_KEY = "AKIAW5BDRKBF6MVTS7X2";
const AWS_SECRET_KEY = "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";
const AWS_REGION = "ap-south-1";

// Init EC2 client
const ec2Client = new EC2Client({
  region: AWS_REGION,
  credentials: {
    accessKeyId: AWS_ACCESS_KEY,
    secretAccessKey: AWS_SECRET_KEY,
  },
});

// API to fetch EC2 instances
app.get('/api/ec2', async (req, res) => {
  try {
    console.log("📡 Calling AWS EC2 DescribeInstances...");
    const command = new DescribeInstancesCommand({});
    const response = await ec2Client.send(command);
    const instances = response.Reservations?.flatMap(r => r.Instances) || [];

    console.log(`✅ Found ${instances.length} EC2 instance(s)`);

    res.json(instances);
  } catch (err) {
    console.error("❌ AWS EC2 call failed:", err);
    res.status(500).json({ error: "Failed to fetch EC2 data", details: err.message });
  }
});

// Start the server
const PORT = 5000;
app.listen(PORT, () => {
  console.log('🚀 Server running on http://localhost:${PORT}');
});