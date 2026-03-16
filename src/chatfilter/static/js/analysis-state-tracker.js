(function() {
    const AnalysisStateTracker = {
        activeAnalysis: false,

        setAnalysisRunning(isRunning) {
            this.activeAnalysis = isRunning;
            console.log('Analysis state changed:', isRunning ? 'running' : 'stopped');
        },

        isAnalysisRunning() {
            return this.activeAnalysis;
        }
    };

    // Prevent closing during active analysis
    window.addEventListener('beforeunload', function(e) {
        if (AnalysisStateTracker.isAnalysisRunning()) {
            // Modern browsers require returnValue to be set
            e.preventDefault();
            e.returnValue = '';

            // Note: Modern browsers don't show custom messages anymore for security reasons
            // They show their own generic message like "Leave site? Changes you made may not be saved"
            return '';
        }
    });

    // Make tracker globally accessible
    window.AnalysisStateTracker = AnalysisStateTracker;
})();
