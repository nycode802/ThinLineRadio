/*
 * *****************************************************************************
 * Copyright (C) 2025 Thinline Dynamic Solutions
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 * ****************************************************************************
 */

import { Component, OnInit, OnDestroy } from '@angular/core';
import { RdioScannerAdminService } from '../admin.service';

export interface SystemAlert {
    id: number;
    alertType: string;
    severity: string;
    title: string;
    message: string;
    data: string;
    createdAt: number;
    createdBy: number;
    dismissed: boolean;
}

export interface FailedCall {
    callId: number;
    systemId: number;
    talkgroupId: number;
    timestamp: number;
    systemLabel: string;
    talkgroupLabel: string;
    talkgroupName: string;
    failureReason?: string;
}

@Component({
    selector: 'rdio-scanner-admin-system-health',
    styleUrls: ['./system-health.component.scss'],
    templateUrl: './system-health.component.html',
})
export class RdioScannerAdminSystemHealthComponent implements OnInit, OnDestroy {
    alerts: SystemAlert[] = [];
    loading = false;
    error: string | null = null;
    
    stats = {
        total: 0,
        critical: 0,
        error: 0,
        warning: 0,
        info: 0
    };

    // Transcription failure specific data
    failedCalls: FailedCall[] = [];
    loadingFailedCalls = false;
    transcriptionFailureThreshold = 10;
    editingThreshold = false;
    newThreshold = 10;
    
    // Alert retention settings
    alertRetentionDays = 5;
    editingRetentionDays = false;
    newRetentionDays = 5;
    
    // Tone detection issue threshold
    toneDetectionIssueThreshold = 5;
    editingToneThreshold = false;
    newToneThreshold = 5;

    private refreshInterval: any;

    constructor(private adminService: RdioScannerAdminService) {}

    ngOnInit(): void {
        this.loadAlerts();
        this.loadThreshold();
        this.loadRetentionDays();
        this.loadToneDetectionThreshold();
        // Auto-refresh every 60 seconds
        this.refreshInterval = setInterval(() => {
            this.loadAlerts();
        }, 60000);
    }

    ngOnDestroy(): void {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
        }
    }

    async loadAlerts(): Promise<void> {
        this.loading = true;
        this.error = null;

        try {
            const response = await this.adminService.getSystemHealth(100, false);
            this.alerts = response.alerts || [];
            this.updateStats();
            
            // Check if there's a transcription_failure alert and load failed calls
            const transcriptionFailureAlert = this.alerts.find(a => a.alertType === 'transcription_failure' && !a.dismissed);
            if (transcriptionFailureAlert) {
                this.loadFailedCalls();
            } else {
                this.failedCalls = [];
            }
        } catch (error: any) {
            this.error = error.message || 'Failed to load system health data';
            this.alerts = [];
        } finally {
            this.loading = false;
        }
    }

    async loadFailedCalls(): Promise<void> {
        this.loadingFailedCalls = true;
        try {
            const response = await this.adminService.getTranscriptionFailures();
            this.failedCalls = response.calls || [];
        } catch (error: any) {
            console.error('Failed to load failed calls:', error);
            this.failedCalls = [];
        } finally {
            this.loadingFailedCalls = false;
        }
    }

    async loadThreshold(): Promise<void> {
        try {
            this.transcriptionFailureThreshold = await this.adminService.getTranscriptionFailureThreshold();
            this.newThreshold = this.transcriptionFailureThreshold;
        } catch (error: any) {
            console.error('Failed to load threshold:', error);
        }
    }

    async loadRetentionDays(): Promise<void> {
        try {
            this.alertRetentionDays = await this.adminService.getAlertRetentionDays();
            this.newRetentionDays = this.alertRetentionDays;
        } catch (error: any) {
            console.error('Failed to load retention days:', error);
        }
    }

    async saveThreshold(): Promise<void> {
        if (this.newThreshold <= 0) {
            alert('Threshold must be a positive number.');
            return;
        }
        try {
            await this.adminService.setTranscriptionFailureThreshold(this.newThreshold);
            this.transcriptionFailureThreshold = this.newThreshold;
            this.editingThreshold = false;
            this.loadAlerts(); // Reload alerts to reflect new threshold
        } catch (error: any) {
            console.error('Failed to save threshold:', error);
            alert('Failed to save threshold: ' + (error.message || 'Unknown error'));
        }
    }

    cancelEditThreshold(): void {
        this.newThreshold = this.transcriptionFailureThreshold;
        this.editingThreshold = false;
    }

    async saveRetentionDays(): Promise<void> {
        if (this.newRetentionDays <= 0) {
            alert('Retention days must be a positive number.');
            return;
        }
        try {
            await this.adminService.setAlertRetentionDays(this.newRetentionDays);
            this.alertRetentionDays = this.newRetentionDays;
            this.editingRetentionDays = false;
        } catch (error: any) {
            console.error('Failed to save retention days:', error);
            alert('Failed to save retention days: ' + (error.message || 'Unknown error'));
        }
    }

    cancelEditRetentionDays(): void {
        this.newRetentionDays = this.alertRetentionDays;
        this.editingRetentionDays = false;
    }

    async loadToneDetectionThreshold(): Promise<void> {
        try {
            this.toneDetectionIssueThreshold = await this.adminService.getToneDetectionIssueThreshold();
            this.newToneThreshold = this.toneDetectionIssueThreshold;
        } catch (error: any) {
            console.error('Failed to load tone detection threshold:', error);
        }
    }

    async saveToneDetectionThreshold(): Promise<void> {
        if (this.newToneThreshold <= 0) {
            alert('Threshold must be a positive number.');
            return;
        }
        try {
            await this.adminService.setToneDetectionIssueThreshold(this.newToneThreshold);
            this.toneDetectionIssueThreshold = this.newToneThreshold;
            this.editingToneThreshold = false;
            this.loadAlerts(); // Reload alerts to reflect new threshold
        } catch (error: any) {
            console.error('Failed to save tone detection threshold:', error);
            alert('Failed to save threshold: ' + (error.message || 'Unknown error'));
        }
    }

    cancelEditToneThreshold(): void {
        this.newToneThreshold = this.toneDetectionIssueThreshold;
        this.editingToneThreshold = false;
    }

    async resetFailures(callIds?: number[]): Promise<void> {
        if (!confirm(callIds ? 'Reset selected transcription failures?' : 'Reset all transcription failures from the last 24 hours?')) {
            return;
        }

        try {
            await this.adminService.resetTranscriptionFailures(callIds);
            await this.loadFailedCalls();
            await this.loadAlerts(); // Reload alerts to update count
        } catch (error: any) {
            console.error('Failed to reset failures:', error);
            alert('Failed to reset failures: ' + (error.message || 'Unknown error'));
        }
    }

    getTranscriptionFailureAlert(): SystemAlert | undefined {
        return this.alerts.find(a => a.alertType === 'transcription_failure' && !a.dismissed);
    }

    private updateStats(): void {
        this.stats = {
            total: this.alerts.length,
            critical: 0,
            error: 0,
            warning: 0,
            info: 0
        };

        this.alerts.forEach(alert => {
            if (alert.severity === 'critical') this.stats.critical++;
            else if (alert.severity === 'error') this.stats.error++;
            else if (alert.severity === 'warning') this.stats.warning++;
            else if (alert.severity === 'info') this.stats.info++;
        });
    }

    getSeverityIcon(severity: string): string {
        switch (severity) {
            case 'critical': return '🚨';
            case 'error': return '❌';
            case 'warning': return '⚠️';
            case 'info': return 'ℹ️';
            default: return '📋';
        }
    }

    getAlertData(alert: SystemAlert): any {
        try {
            return JSON.parse(alert.data || '{}');
        } catch {
            return {};
        }
    }

    hasAlertData(alert: SystemAlert): boolean {
        const data = this.getAlertData(alert);
        return data && Object.keys(data).length > 0;
    }

    formatDate(timestamp: number): string {
        return new Date(timestamp).toLocaleString();
    }

    playingCallId: number | null = null;
    audioElement: HTMLAudioElement | null = null;

    playCall(callId: number): void {
        // If already playing this call, stop it
        if (this.playingCallId === callId && this.audioElement) {
            this.audioElement.pause();
            this.audioElement = null;
            this.playingCallId = null;
            return;
        }

        // Stop any currently playing audio
        if (this.audioElement) {
            this.audioElement.pause();
            this.audioElement = null;
        }

        // Create new audio element
        const audio = new Audio();
        const audioUrl = this.adminService.getCallAudioUrl(callId);
        
        // Add authorization token to the URL as a query parameter
        // Since we can't set headers on Audio element, we'll need to use a different approach
        // Actually, we can use a blob URL by fetching with headers first
        this.loadAndPlayAudio(callId, audio);
    }

    async loadAndPlayAudio(callId: number, audio: HTMLAudioElement): Promise<void> {
        try {
            // Fetch audio with authentication headers
            const audioUrl = this.adminService.getCallAudioUrl(callId);
            const headers = this.adminService.getFetchHeaders();
            const response = await fetch(audioUrl, {
                headers: headers,
            });

            if (!response.ok) {
                throw new Error(`Failed to load audio: ${response.statusText}`);
            }

            const blob = await response.blob();
            const blobUrl = URL.createObjectURL(blob);
            
            audio.src = blobUrl;
            audio.onended = () => {
                URL.revokeObjectURL(blobUrl);
                this.audioElement = null;
                this.playingCallId = null;
            };
            audio.onerror = () => {
                URL.revokeObjectURL(blobUrl);
                this.audioElement = null;
                this.playingCallId = null;
                alert('Failed to play audio');
            };

            this.audioElement = audio;
            this.playingCallId = callId;
            await audio.play();
        } catch (error: any) {
            console.error('Failed to play call audio:', error);
            alert('Failed to play audio: ' + (error.message || 'Unknown error'));
            this.audioElement = null;
            this.playingCallId = null;
        }
    }

    isPlaying(callId: number): boolean {
        return this.playingCallId === callId && this.audioElement !== null && !this.audioElement.paused;
    }
}

