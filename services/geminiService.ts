import { GoogleGenAI, GenerateContentResponse } from "@google/genai";

// Helper to ensure we don't crash if API key is missing, though in production it's expected
const getAIClient = () => {
  const apiKey = process.env.API_KEY;
  if (!apiKey) {
    throw new Error("API_KEY environment variable is not set.");
  }
  return new GoogleGenAI({ apiKey });
};

export const generateRedTeamAdvice = async (prompt: string): Promise<string> => {
  try {
    const ai = getAIClient();
    const response: GenerateContentResponse = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: prompt,
      config: {
        systemInstruction: "You are a highly skilled and ethical Red Team Operations security expert. Your goal is to help the user understand security commands, generate payloads for authorized testing, and explain vulnerabilities. Keep answers concise, technical, and formatted for a cheatsheet context. Always prioritize educational value and safety.",
        temperature: 0.7,
      },
    });
    
    return response.text || "No response generated.";
  } catch (error) {
    console.error("Gemini API Error:", error);
    return "Error contacting HQ (Gemini API). Please check your API Key or connection.";
  }
};