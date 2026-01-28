require('dotenv').config();

// ============================================================================
// CRASH VISIBILITY - Must be at the very top
// ============================================================================
process.on("uncaughtException", (e) => {
  console.error("❌ UNCAUGHT EXCEPTION:", e);
  console.error("Stack:", e.stack);
  process.exit(1);
});

process.on("unhandledRejection", (e) => {
  console.error("❌ UNHANDLED REJECTION:", e);
  process.exit(1);
});

process.on("exit", (code) => {
  console.log("🚪 PROCESS EXIT - Code:", code);
});

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');
const OpenAI = require('openai');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = parseInt(process.env.PORT, 10) || 3000;

// Initialize Stripe only if key is present (optional for deployment)
let stripe = null;
if (process.env.STRIPE_SECRET_KEY) {
  try {
    stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
    console.log('✅ Stripe initialized');
  } catch (err) {
    console.error('⚠️ Stripe initialization failed:', err.message);
  }
} else {
  console.log('⚠️ STRIPE_SECRET_KEY not set - Stripe disabled');
}

// CRITICAL: Raw body for Stripe webhooks (must be before express.json())
app.post('/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe) {
    console.error('❌ Stripe not initialized (missing STRIPE_SECRET_KEY)');
    return res.status(503).json({ error: 'Stripe not configured' });
  }

  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  if (!webhookSecret) {
    console.error('❌ STRIPE_WEBHOOK_SECRET not set');
    return res.status(500).json({ error: 'Webhook secret not configured' });
  }

  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    console.log(`✅ Stripe webhook received: ${event.type}`);
  } catch (err) {
    console.error(`❌ Webhook signature verification failed: ${err.message}`);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle different event types
  switch (event.type) {
    case 'checkout.session.completed':
      console.log('💳 Checkout session completed:', event.data.object.id);
      // TODO: Update user subscription tier in database
      break;

    case 'customer.subscription.created':
      console.log('📝 Subscription created:', event.data.object.id);
      break;

    case 'customer.subscription.updated':
      console.log('🔄 Subscription updated:', event.data.object.id);
      break;

    case 'customer.subscription.deleted':
      console.log('❌ Subscription deleted:', event.data.object.id);
      break;

    case 'invoice.payment_succeeded':
      console.log('✅ Payment succeeded:', event.data.object.id);
      break;

    case 'invoice.payment_failed':
      console.log('💸 Payment failed:', event.data.object.id);
      break;

    default:
      console.log(`⚠️ Unhandled event type: ${event.type}`);
  }

  res.json({ received: true });
});

// JSON parsing for all other routes
app.use(express.json());

// Initialize Supabase client (admin for server-side operations)
let supabaseAdmin;
let openai;

try {
  supabaseAdmin = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
  );
  console.log('✅ Supabase client initialized');
} catch (err) {
  console.error('⚠️  Supabase initialization warning:', err.message);
}

// Initialize OpenAI client
try {
  openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
  });
  console.log('✅ OpenAI client initialized');
} catch (err) {
  console.error('⚠️  OpenAI initialization warning:', err.message);
}

// Configure multer for file uploads (memory storage)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024 // 50MB max file size
  }
});

// CORS middleware
app.use(cors());

// Auth middleware
const authenticateUser = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.substring(7);

    // Verify token with Supabase
    const { data: { user }, error } = await supabaseAdmin.auth.getUser(token);

    if (error || !user) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    req.user = user;
    next();
  } catch (err) {
    console.error('Auth error:', err);
    res.status(401).json({ error: 'Authentication failed' });
  }
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    message: 'Backend V2 - Minimal'
  });
});

// Test Supabase connection
app.get('/api/test-db', async (req, res) => {
  try {
    const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

    const { data, error } = await supabase
      .from('users')
      .select('count')
      .limit(1);

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    res.json({ message: 'Supabase connected!', data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// RECORDING ENDPOINTS - Priority 1
// ============================================================================

/**
 * POST /api/voice-command/transcribe
 * SYNC transcription for voice commands (3 second snippets)
 * Returns transcript immediately (no database storage)
 */
app.post('/api/voice-command/transcribe', authenticateUser, upload.single('audio'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No audio file provided' });
    }

    console.log(`🎤 Voice command transcription request from user ${req.user.id}, size: ${req.file.size} bytes`);

    // Create a File-like object for OpenAI API
    const audioFile = new File([req.file.buffer], req.file.originalname, {
      type: 'audio/wav'
    });

    // Call Whisper API (synchronous - waits for result)
    const transcription = await openai.audio.transcriptions.create({
      file: audioFile,
      model: 'whisper-1',
      language: 'en'
    });

    console.log(`✅ Voice command transcribed: "${transcription.text}"`);

    // Return transcript immediately
    res.json({
      success: true,
      transcript: transcription.text
    });

  } catch (err) {
    console.error('❌ Voice command transcription error:', err);
    res.status(500).json({ error: 'Failed to transcribe voice command' });
  }
});

/**
 * POST /api/recordings/upload
 * Upload audio file, transcribe with Whisper, save to Supabase
 */
app.post('/api/recordings/upload', authenticateUser, upload.single('audio'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No audio file provided' });
    }

    const { duration } = req.body; // Duration in seconds from app
    const userId = req.user.id;
    const recordingId = uuidv4();

    console.log(`📤 Uploading recording for user ${userId}, duration: ${duration}s, size: ${req.file.size} bytes`);

    // PHASE 3: Storage limit enforcement (server-side check)
    const capBytes = parseInt(process.env.STORAGE_CAP_BYTES) || 262144000; // 250 MB default

    const { data: usageData, error: usageError } = await supabaseAdmin
      .from('user_storage_usage')
      .select('total_bytes')
      .eq('user_id', userId)
      .single();

    const currentUsage = usageData?.total_bytes || 0;
    const newTotal = currentUsage + req.file.size;

    if (newTotal > capBytes) {
      console.log(`🚫 Storage limit exceeded: ${newTotal} > ${capBytes} bytes`);
      return res.status(402).json({
        code: 'STORAGE_LIMIT',
        error: 'Storage limit exceeded',
        total_bytes: currentUsage,
        cap_bytes: capBytes,
        upload_size: req.file.size
      });
    }

    console.log(`✅ Storage check passed: ${newTotal} / ${capBytes} bytes`);

    // 1. Upload audio to Supabase Storage
    const fileName = `${recordingId}-${Date.now()}.${req.file.originalname.split('.').pop()}`;
    const filePath = `${userId}/${fileName}`;

    const { data: uploadData, error: uploadError } = await supabaseAdmin
      .storage
      .from('recordings')
      .upload(filePath, req.file.buffer, {
        contentType: req.file.mimetype,
        upsert: false
      });

    if (uploadError) {
      console.error('Storage upload error:', uploadError);
      return res.status(500).json({ error: 'Failed to upload audio file' });
    }

    // Get public URL for the uploaded file
    const { data: { publicUrl } } = supabaseAdmin
      .storage
      .from('recordings')
      .getPublicUrl(filePath);

    console.log(`✅ Audio uploaded to storage: ${filePath}`);

    // 2. Create recording record in database (status: 'processing')
    // Store the storage path, not the public URL (we'll generate signed URLs when fetching)
    const { data: recording, error: dbError } = await supabaseAdmin
      .from('recordings')
      .insert({
        id: recordingId,
        user_id: userId,
        audio_url: filePath, // Store the path, not public URL
        filename: req.file.originalname,
        duration_seconds: parseInt(duration) || 0,
        file_size_bytes: req.file.size,
        status: 'processing'
      })
      .select()
      .single();

    if (dbError) {
      console.error('Database insert error:', dbError);
      return res.status(500).json({ error: 'Failed to save recording metadata' });
    }

    console.log(`💾 Recording saved to DB: ${recordingId}`);

    // Generate signed URL for the response (valid for 1 hour)
    const { data: signedUrlData } = await supabaseAdmin
      .storage
      .from('recordings')
      .createSignedUrl(filePath, 3600); // 1 hour expiry

    // 3. Transcribe audio with Whisper (WAIT for voice commands - they need immediate response)
    console.log(`🎙️  Starting transcription for ${recordingId}`);

    const audioFile = new File([req.file.buffer], req.file.originalname, {
      type: req.file.mimetype
    });

    const transcription = await openai.audio.transcriptions.create({
      file: audioFile,
      model: 'whisper-1',
      language: 'en'
    });

    console.log(`✅ Transcription complete for ${recordingId}: ${transcription.text}`);

    // Update recording with transcription
    await supabaseAdmin
      .from('recordings')
      .update({
        transcription: transcription.text,
        status: 'completed'
      })
      .eq('id', recordingId);

    console.log(`💾 Transcription saved for ${recordingId}`);

    // Return response with transcription included
    res.status(201).json({
      success: true,
      recording: {
        id: recording.id,
        audio_url: signedUrlData?.signedUrl || filePath,
        duration_seconds: recording.duration_seconds,
        transcription: transcription.text,
        status: 'completed',
        created_at: recording.created_at
      }
    });

  } catch (err) {
    console.error('❌ Upload error:', err);
    res.status(500).json({ error: 'Failed to upload recording' });
  }
});

/**
 * Async transcription function - runs after upload response is sent
 */
async function transcribeRecordingAsync(recordingId, audioBuffer, filename) {
  try {
    console.log(`🎙️  Starting transcription for ${recordingId}`);

    // Create a File-like object for OpenAI API
    const audioFile = new File([audioBuffer], filename, {
      type: filename.endsWith('.wav') ? 'audio/wav' : 'audio/mp4'
    });

    // Call Whisper API
    const transcription = await openai.audio.transcriptions.create({
      file: audioFile,
      model: 'whisper-1',
      language: 'en'
    });

    console.log(`✅ Transcription complete for ${recordingId}: ${transcription.text.substring(0, 100)}...`);

    // Update recording with transcription
    const { error: updateError } = await supabaseAdmin
      .from('recordings')
      .update({
        transcription: transcription.text,
        status: 'completed',
        updated_at: new Date().toISOString()
      })
      .eq('id', recordingId);

    if (updateError) {
      console.error('Failed to update transcription:', updateError);
    } else {
      console.log(`💾 Transcription saved for ${recordingId}`);
    }

  } catch (err) {
    console.error(`❌ Transcription error for ${recordingId}:`, err);

    // Mark as error in database
    await supabaseAdmin
      .from('recordings')
      .update({
        status: 'error',
        updated_at: new Date().toISOString()
      })
      .eq('id', recordingId);
  }
}

/**
 * GET /api/recordings
 * Fetch all recordings for authenticated user
 */
app.get('/api/recordings', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    const limit = parseInt(req.query.limit) || 50;

    const { data: recordings, error } = await supabaseAdmin
      .from('recordings')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(limit);

    if (error) {
      console.error('Database query error:', error);
      return res.status(500).json({ error: 'Failed to fetch recordings' });
    }

    // Generate signed URLs for each recording (valid for 1 hour)
    const recordingsWithSignedUrls = await Promise.all(
      recordings.map(async (recording) => {
        if (recording.audio_url) {
          const { data: signedUrlData } = await supabaseAdmin
            .storage
            .from('recordings')
            .createSignedUrl(recording.audio_url, 3600); // 1 hour expiry

          return {
            ...recording,
            audio_url: signedUrlData?.signedUrl || recording.audio_url
          };
        }
        return recording;
      })
    );

    res.json({
      success: true,
      recordings: recordingsWithSignedUrls || []
    });

  } catch (err) {
    console.error('❌ Fetch recordings error:', err);
    res.status(500).json({ error: 'Failed to fetch recordings' });
  }
});

/**
 * GET /api/recordings/:id
 * Get single recording details
 */
app.get('/api/recordings/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    const { data: recording, error } = await supabaseAdmin
      .from('recordings')
      .select('*')
      .eq('id', id)
      .eq('user_id', userId)
      .single();

    if (error || !recording) {
      return res.status(404).json({ error: 'Recording not found' });
    }

    res.json({
      success: true,
      recording
    });

  } catch (err) {
    console.error('❌ Fetch recording error:', err);
    res.status(500).json({ error: 'Failed to fetch recording' });
  }
});

/**
 * DELETE /api/recordings/:id
 * Delete a recording
 */
app.delete('/api/recordings/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    // Get recording to find audio file path
    const { data: recording, error: fetchError } = await supabaseAdmin
      .from('recordings')
      .select('audio_url')
      .eq('id', id)
      .eq('user_id', userId)
      .single();

    if (fetchError || !recording) {
      return res.status(404).json({ error: 'Recording not found' });
    }

    // Delete from database
    const { error: deleteError } = await supabaseAdmin
      .from('recordings')
      .delete()
      .eq('id', id)
      .eq('user_id', userId);

    if (deleteError) {
      console.error('Database delete error:', deleteError);
      return res.status(500).json({ error: 'Failed to delete recording' });
    }

    // TODO: Delete from storage (extract path from audio_url)
    // const filePath = extractPathFromUrl(recording.audio_url);
    // await supabaseAdmin.storage.from('recordings').remove([filePath]);

    res.json({
      success: true,
      message: 'Recording deleted'
    });

  } catch (err) {
    console.error('❌ Delete recording error:', err);
    res.status(500).json({ error: 'Failed to delete recording' });
  }
});

// ============================================================================
// CHAT ENDPOINTS - Priority 3
// ============================================================================

/**
 * POST /api/chat
 * Chat with AI based on retrieval mode (hybrid/memory/web)
 * Supports conversation history for multi-turn conversations
 */
app.post('/api/chat', authenticateUser, async (req, res) => {
  try {
    const {
      message,
      retrievalMode = 'hybrid',
      assistantName = 'Assistant',
      voiceGender = 'female',
      voiceAttitude = 'helpful',
      conversationHistory = [] // NEW: Accept conversation history from client
    } = req.body;
    const userId = req.user.id;

    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    console.log(`💬 Chat request from user ${userId}, mode: ${retrievalMode}`);
    console.log('   Personality -> Name: ' + assistantName + ', Gender: ' + voiceGender + ', Attitude: ' + voiceAttitude);
    console.log('   Conversation history: ' + conversationHistory.length + ' messages');

    // Build personality description
    const genderDesc = voiceGender === 'male' ? 'male' : 'female';
    const attitudeDesc = voiceAttitude === 'friendly' ? 'friendly and warm' : voiceAttitude === 'formal' ? 'professional and formal' : 'helpful and supportive';
    const personality = `You are ${assistantName}, a ${genderDesc} ${attitudeDesc} AI assistant.`;

    // Build context based on retrieval mode
    let context = '';

    if (retrievalMode === 'memory' || retrievalMode === 'hybrid') {
      // Fetch recent recordings for context (simple text search for now)
      const { data: recordings } = await supabaseAdmin
        .from('recordings')
        .select('transcription, created_at')
        .eq('user_id', userId)
        .eq('status', 'completed')
        .not('transcription', 'is', null)
        .order('created_at', { ascending: false })
        .limit(5);

      if (recordings && recordings.length > 0) {
        context = recordings
          .map(r => `[${new Date(r.created_at).toLocaleDateString()}] ${r.transcription}`)
          .join('\n\n');
      }
    }

    // Prepare system prompt based on mode
    let systemPrompt = '';
    if (retrievalMode === 'memory') {
      systemPrompt = `${personality} You have access to the user's voice recordings. Use the following transcriptions to answer questions:\n\n${context || 'No recordings available yet.'}`;
    } else if (retrievalMode === 'web') {
      systemPrompt = `${personality} Answer questions using your general knowledge and web information.`;
    } else {
      // hybrid
      systemPrompt = `${personality} You have access to the user's voice recordings and general knowledge. Use both to provide comprehensive answers.\n\nRecent recordings:\n${context || 'No recordings available yet.'}`;
    }

    // Build messages array with conversation history
    const messages = [
      { role: 'system', content: systemPrompt },
      ...conversationHistory, // Include full conversation history
      { role: 'user', content: message }
    ];

    // Call OpenAI Chat API
    const completion = await openai.chat.completions.create({
      model: 'gpt-4',
      messages: messages,
      temperature: 0.7,
      max_tokens: 500,
    });

    const response = completion.choices[0].message.content;

    res.json({
      success: true,
      response,
      mode: retrievalMode,
      context_used: retrievalMode !== 'web'
    });

  } catch (err) {
    console.error('❌ Chat error:', err);
    res.status(500).json({ error: 'Failed to process chat message' });
  }
});

// ============================================================================
// USER PREFERENCES ENDPOINTS - Priority 4
// ============================================================================

/**
 * GET /api/user/preferences
 * Get user's settings preferences
 */
app.get('/api/user/preferences', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;

    const { data: preferences, error } = await supabaseAdmin
      .from('user_preferences')
      .select('*')
      .eq('user_id', userId)
      .single();

    if (error && error.code !== 'PGRST116') { // PGRST116 = no rows found
      console.error('Database query error:', error);
      return res.status(500).json({ error: 'Failed to fetch preferences' });
    }

    // Return defaults if no preferences exist yet
    if (!preferences) {
      return res.json({
        success: true,
        preferences: {
          assistant_name: 'Assistant',
          voice_gender: 'female',
          voice_attitude: 'helpful',
          retrieval_mode: 'hybrid',
          tap_detection_enabled: true,
          tap_sensitivity: 'medium',
          double_tap_action: 'record',
          triple_tap_action: 'pause',
        }
      });
    }

    res.json({
      success: true,
      preferences
    });

  } catch (err) {
    console.error('❌ Fetch preferences error:', err);
    res.status(500).json({ error: 'Failed to fetch preferences' });
  }
});

/**
 * POST /api/user/preferences
 * Save/update user's settings preferences
 */
app.post('/api/user/preferences', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    const {
      assistant_name,
      voice_gender,
      voice_attitude,
      retrieval_mode,
      tap_detection_enabled,
      tap_sensitivity,
      double_tap_action,
      triple_tap_action,
    } = req.body;

    // Check if preferences exist
    const { data: existing } = await supabaseAdmin
      .from('user_preferences')
      .select('user_id')
      .eq('user_id', userId)
      .single();

    const preferencesData = {
      user_id: userId,
      assistant_name,
      voice_gender,
      voice_attitude,
      retrieval_mode,
      tap_detection_enabled,
      tap_sensitivity,
      double_tap_action,
      triple_tap_action,
      updated_at: new Date().toISOString()
    };

    let result;
    if (existing) {
      // Update existing preferences
      result = await supabaseAdmin
        .from('user_preferences')
        .update(preferencesData)
        .eq('user_id', userId)
        .select()
        .single();
    } else {
      // Insert new preferences
      result = await supabaseAdmin
        .from('user_preferences')
        .insert(preferencesData)
        .select()
        .single();
    }

    if (result.error) {
      console.error('Database error:', result.error);
      return res.status(500).json({ error: 'Failed to save preferences' });
    }

    res.json({
      success: true,
      preferences: result.data
    });

  } catch (err) {
    console.error('❌ Save preferences error:', err);
    res.status(500).json({ error: 'Failed to save preferences' });
  }
});

// Auth endpoints
app.post('/api/auth/signup', async (req, res) => {
  try {
    console.log('📝 Signup request received:', req.body.email);
    const { email, password, name } = req.body;

    if (!email || !password) {
      console.log('❌ Missing email or password');
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

    // Sign up with Supabase Auth
    const { data: authData, error: authError } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          name: name || null
        }
      }
    });

    if (authError) {
      console.log('❌ Supabase signup error:', authError.message);
      return res.status(400).json({ error: authError.message });
    }

    console.log('✅ Signup successful:', authData.user.id);
    // Return user data and session token
    res.json({
      token: authData.session.access_token,
      user: {
        id: authData.user.id,
        email: authData.user.email,
        name: authData.user.user_metadata?.name,
        created_at: authData.user.created_at
      }
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    console.log('🔐 Login request received:', req.body.email);
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

    // Sign in with Supabase Auth
    const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
      email,
      password
    });

    if (authError) {
      console.log('❌ Login failed:', authError.message);
      return res.status(401).json({ error: authError.message });
    }

    console.log('✅ Login successful:', authData.user.id);
    // Return user data and session token
    res.json({
      token: authData.session.access_token,
      user: {
        id: authData.user.id,
        email: authData.user.email,
        name: authData.user.user_metadata?.name,
        created_at: authData.user.created_at
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/auth/reset-password
 * Request password reset email
 */
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    console.log('🔄 Password reset request:', req.body.email);
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: 'spokennotesclean://reset-password',
    });

    if (error) {
      console.log('❌ Password reset error:', error.message);
      return res.status(400).json({ error: error.message });
    }

    console.log('✅ Password reset email sent to:', email);
    res.json({
      success: true,
      message: 'Password reset email sent. Check your inbox.'
    });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * TTS - Generate speech from text (Premium feature)
 */
app.post('/api/tts', authenticateUser, async (req, res) => {
  try {
    const { text, voiceGender = 'female', voiceSelection = 'voice1' } = req.body;

    if (!text) {
      return res.status(400).json({ error: 'Text is required' });
    }

    // Map gender + accent to OpenAI voice
    const voiceKey = `${voiceGender}-${voiceSelection}`;
    const voiceMapping = {
      // Female voices
      'female-voice1': 'nova',     // American - warm, engaging
      'female-voice2': 'shimmer',  // British - soft, clear
      'female-voice3': 'nova',     // Australian - use nova
      'female-voice4': 'shimmer',  // Indian - use shimmer
      // Male voices
      'male-voice1': 'onyx',       // American - deep, authoritative
      'male-voice2': 'echo',       // British - clear, professional
      'male-voice3': 'onyx',       // Australian - use onyx
      'male-voice4': 'fable',      // Indian - balanced, clear
    };

    const voice = voiceMapping[voiceKey] || 'nova';

    // Call OpenAI TTS API
    const mp3 = await openai.audio.speech.create({
      model: 'tts-1',
      voice: voice,
      input: text,
      speed: 1.0,
    });

    // Stream audio back to client
    const buffer = Buffer.from(await mp3.arrayBuffer());

    res.set({
      'Content-Type': 'audio/mpeg',
      'Content-Length': buffer.length,
    });

    res.send(buffer);

  } catch (error) {
    console.error('❌ TTS error:', error);
    res.status(500).json({
      error: 'Failed to generate speech',
      message: error.message
    });
  }
});

// ============================================================================
// BILLING/METERING ENDPOINTS
// ============================================================================

/**
 * GET /api/billing/usage
 * Returns current storage usage for the authenticated user
 * Reads from user_storage_usage view (combines audio + text bytes)
 */
app.get('/api/billing/usage', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    const capBytes = parseInt(process.env.STORAGE_CAP_BYTES) || 262144000; // 250 MB default

    console.log(`📊 Storage usage request from user ${userId}`);

    // Query the user_storage_usage view
    const { data, error } = await supabaseAdmin
      .from('user_storage_usage')
      .select('*')
      .eq('user_id', userId)
      .single();

    if (error && error.code !== 'PGRST116') { // PGRST116 = no rows (user has no uploads yet)
      console.error('❌ Database query error:', error);
      return res.status(500).json({ error: 'Failed to fetch storage usage' });
    }

    // If no data, user has 0 bytes used
    const totalBytes = data?.total_bytes || 0;
    const audioBytes = data?.audio_bytes || 0;
    const textBytes = data?.text_bytes || 0;

    const percentUsed = Math.round((totalBytes / capBytes) * 100);

    // Determine alert level
    let alertLevel = 'none';
    if (percentUsed >= 100) {
      alertLevel = 'blocked';
    } else if (percentUsed >= 90) {
      alertLevel = 'critical';
    } else if (percentUsed >= 70) {
      alertLevel = 'warning';
    }

    const usage = {
      total_bytes: totalBytes,
      audio_bytes: audioBytes,
      text_bytes: textBytes,
      cap_bytes: capBytes,
      percent_used: percentUsed,
      alert_level: alertLevel,
      tier: 'free' // TODO: Read from user subscription table when implemented
    };

    console.log(`✅ Usage: ${totalBytes} / ${capBytes} bytes (${percentUsed}%)`);

    res.json({
      success: true,
      usage
    });

  } catch (err) {
    console.error('❌ Billing usage error:', err);
    res.status(500).json({ error: 'Failed to fetch storage usage' });
  }
});

// Start server
console.log('📍 About to call app.listen() on port', PORT);
const server = app.listen(PORT, '0.0.0.0')
  .on('listening', () => {
    console.log(`🚀 Backend V2 running on http://0.0.0.0:${PORT}`);
    console.log(`📝 Health: http://localhost:${PORT}/health`);
    console.log('✅ Server is listening, event loop active');
  })
  .on('error', (err) => {
    console.error('❌ Server startup error:', err);
    process.exit(1);
  });

// Keep process alive - prevent empty event loop exit
setInterval(() => {
  // Keepalive heartbeat
}, 30000);

server.on('error', (err) => {
  console.error('❌ Server error:', err);
  process.exit(1);
});

