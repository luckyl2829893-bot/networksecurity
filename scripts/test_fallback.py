import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add project root to path
sys.path.append(os.getcwd())

from networksecurity.utils.ai_agent import PhishingAIAgent

class TestResilienceArchitecture(unittest.TestCase):
    
    def setUp(self):
        self.agent = PhishingAIAgent()
        self.test_data = {
            "query": "http://paypal-security-update.com",
            "input_type": "url",
            "risk_score": 85,
            "heuristic_reasons": ["Brand Spoofing", "IP Address detected"],
            "db_results": {}
        }

    @patch('requests.post')
    def test_tier1_gemini_success(self, mock_post):
        """Scenario: Gemini is healthy and works."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'candidates': [{'content': {'parts': [{'text': "Gemini analysis content"}]}}]
        }
        mock_post.return_value = mock_response
        
        self.agent.gemini_key = "valid_key"
        result = self.agent.generate_detailed_analysis(**self.test_data)
        
        self.assertEqual(result['tier'], 1)
        self.assertEqual(result['model_used'], "Gemini 1.5 Flash")
        self.assertIn("Gemini analysis", result['analysis'])

    @patch('requests.post')
    def test_tier2_fallback_to_llama(self, mock_post):
        """Scenario: Gemini fails (403/Invalid Key) -> Falls to Llama 3.1."""
        self.agent.gemini_key = "dummy_key" # Ensure Tier 1 is attempted
        
        # First call (Gemini) fails
        mock_gemini_fail = MagicMock()
        mock_gemini_fail.status_code = 403
        
        # Second call (Ollama Llama) succeeds
        mock_llama_success = MagicMock()
        mock_llama_success.status_code = 200
        mock_llama_success.json.return_value = {"response": "Llama 3.1 reasoning content"}
        
        mock_post.side_effect = [mock_gemini_fail, mock_llama_success]
        
        result = self.agent.generate_detailed_analysis(**self.test_data)
        
        self.assertEqual(result['tier'], 2)
        self.assertEqual(result['model_used'], "Llama 3.1 (8B)")
        self.assertIn("Llama 3.1", result['analysis'])

    @patch('requests.post')
    def test_tier3_fallback_to_phi(self, mock_post):
        """Scenario: Gemini fails, Llama 3.1 fails -> Falls to Phi-3."""
        self.agent.gemini_key = "dummy_key" # Ensure Tier 1 is attempted
        
        # 1. Gemini fail
        mock_gemini_fail = MagicMock()
        mock_gemini_fail.status_code = 500
        
        # 2. Llama 3.1 fail
        mock_llama_fail = MagicMock()
        mock_llama_fail.status_code = 404
        
        # 3. Phi-3 success
        mock_phi_success = MagicMock()
        mock_phi_success.status_code = 200
        mock_phi_success.json.return_value = {"response": "Phi-3 reasoning content"}
        
        mock_post.side_effect = [mock_gemini_fail, mock_llama_fail, mock_phi_success]
        
        result = self.agent.generate_detailed_analysis(**self.test_data)
        
        self.assertEqual(result['tier'], 3)
        self.assertEqual(result['model_used'], "Phi-3 Mini")
        self.assertIn("Phi-3", result['analysis'])

    @patch('requests.post')
    def test_tier4_absolute_fallback(self, mock_post):
        """Scenario: Everything fails (No internet, No Ollama) -> Falls to Rules."""
        self.agent.gemini_key = "dummy_key" # Ensure Tier 1 is attempted
        
        # All requests throw connection errors
        mock_post.side_effect = Exception("Connection Refused")
        
        result = self.agent.generate_detailed_analysis(**self.test_data)
        
        self.assertEqual(result['tier'], 4)
        self.assertEqual(result['model_used'], "Rule-based Engine")
        self.assertIn("Rule-based", result['analysis'])
        self.assertIn("85/100", result['analysis'])

if __name__ == "__main__":
    unittest.main()
