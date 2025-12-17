from typing import Dict, Any, List
from analysis_engine import AnalysisEngine
from datetime import datetime

class ReportGenerator:
    def __init__(self, analysis_engine: AnalysisEngine):
        self.analysis_engine = analysis_engine
    
    def generate_comprehensive_report(self, dataset: List[Dict]) -> Dict[str, Any]:
        analysis_results = self.analysis_engine.process_dataset(dataset)
        
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'report_type': 'comprehensive_analysis'
            },
            'executive_summary': self._generate_executive_summary(analysis_results),
            'detailed_analysis': analysis_results,
            'recommendations': self._generate_recommendations(analysis_results)
        }
        
        return report
    
    def _generate_executive_summary(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        total = analysis['total_records']
        valid = analysis['valid_count']
        invalid = analysis['invalid_count']
        
        return {
            'total_processed': total,
            'data_quality_score': round((valid / total) * 100, 2) if total > 0 else 0,
            'key_findings': self._extract_key_findings(analysis['insights']),
            'overall_assessment': self._assess_data_quality(valid, invalid)
        }
    
    def _extract_key_findings(self, insights: Dict[str, Any]) -> List[str]:
        findings = []
        
        if 'field_statistics' in insights:
            stats = insights['field_statistics']
            
            for field, field_stats in stats.items():
                presence_pct = field_stats.get('presence_percentage', 0)
                
                if presence_pct < 50:
                    findings.append(f"Low data completeness for field '{field}': {presence_pct}%")
                elif presence_pct > 90:
                    findings.append(f"Excellent data completeness for field '{field}': {presence_pct}%")
        
        return findings
    
    def _assess_data_quality(self, valid_count: int, invalid_count: int) -> str:
        total = valid_count + invalid_count
        if total == 0:
            return "No data to assess"
        
        quality_ratio = valid_count / total
        
        if quality_ratio >= 0.9:
            return "Excellent data quality"
        elif quality_ratio >= 0.7:
            return "Good data quality"
        elif quality_ratio >= 0.5:
            return "Fair data quality - needs improvement"
        else:
            return "Poor data quality - significant issues need addressing"
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[Dict[str, str]]:
        recommendations = []
        
        invalid_count = analysis['invalid_count']
        total_count = analysis['total_records']
        
        if invalid_count > 0:
            error_rate = (invalid_count / total_count) * 100
            recommendations.append({
                'category': 'Data Quality',
                'recommendation': f'Implement data validation at source. Current error rate: {error_rate:.1f}%',
                'priority': 'high' if error_rate > 10 else 'medium'
            })
        
        if 'insights' in analysis and 'field_statistics' in analysis['insights']:
            for field, stats in analysis['insights']['field_statistics'].items():
                completeness = stats.get('presence_percentage', 0)
                if completeness < 60:
                    recommendations.append({
                        'category': 'Data Completeness',
                        'recommendation': f'Improve collection process for field: {field}',
                        'priority': 'medium'
                    })
        
        return recommendations