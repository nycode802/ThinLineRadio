/*
 * *****************************************************************************
 * Copyright (C) 2019-2024 Chrystian Huot <chrystian@huot.qc.ca>
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

import { CdkDragDrop, moveItemInArray } from '@angular/cdk/drag-drop';
import { Component, EventEmitter, Input, Output, QueryList, ViewChildren } from '@angular/core';
import { FormArray, FormControl, FormGroup } from '@angular/forms';
import { MatExpansionPanel } from '@angular/material/expansion';
import { MatSelectChange } from '@angular/material/select';
import { RdioScannerAdminService, Group, Tag } from '../../../admin.service';

@Component({
    selector: 'rdio-scanner-admin-system',
    templateUrl: './system.component.html',
})
export class RdioScannerAdminSystemComponent {
    @Input() form = new FormGroup({});

    @Input() groups: Group[] = [];

    @Input() tags: Tag[] = [];

    @Output() add = new EventEmitter<void>();

    @Output() remove = new EventEmitter<void>();

    // Bulk selection state
    selectedTalkgroupIndices: Set<number> = new Set();
    bulkAssignGroupId: number | null = null;
    bulkAssignTagId: number | null = null;

    get sites(): FormGroup[] {
        const sites = this.form.get('sites') as FormArray | null;

        return sites?.controls
            .sort((a, b) => (a.value.order || 0) - (b.value.order || 0)) as FormGroup[];
    }

    get talkgroups(): FormGroup[] {
        const talkgroups = this.form.get('talkgroups') as FormArray | null;

        return talkgroups?.controls
            .sort((a, b) => (a.value.order || 0) - (b.value.order || 0)) as FormGroup[];
    }

    get units(): FormGroup[] {
        const units = this.form.get('units') as FormArray | null;

        return units?.controls
            .sort((a, b) => (a.value.order || 0) - (b.value.order || 0)) as FormGroup[];
    }

    get hasSelectedTalkgroups(): boolean {
        return this.selectedTalkgroupIndices.size > 0;
    }

    get allTalkgroupsSelected(): boolean {
        return this.talkgroups.length > 0 && this.selectedTalkgroupIndices.size === this.talkgroups.length;
    }

    @ViewChildren(MatExpansionPanel) private panels: QueryList<MatExpansionPanel> | undefined;

    constructor(private adminService: RdioScannerAdminService) {
    }

    addSite(): void {
        const sites = this.form.get('sites') as FormArray | null;

        sites?.insert(0, this.adminService.newSiteForm());

        this.form.markAsDirty();
    }

    addTalkgroup(): void {
        const talkgroups = this.form.get('talkgroups') as FormArray | null;

        talkgroups?.insert(0, this.adminService.newTalkgroupForm());

        this.form.markAsDirty();
    }

    addUnit(): void {
        const units = this.form.get('units') as FormArray | null;

        units?.insert(0, this.adminService.newUnitForm());

        this.form.markAsDirty();
    }

    blacklistTalkgroup(index: number): void {
        const talkgroup = this.talkgroups[index];

        const id = talkgroup.value.id;

        if (typeof id !== 'number') {
            return;
        }

        const blacklists = this.form.get('blacklists') as FormControl | null;

        blacklists?.setValue(blacklists.value?.trim() ? `${blacklists.value},${id}` : `${id}`);

        this.removeTalkgroup(index);
    }

    closeAll(): void {
        this.panels?.forEach((panel) => panel.close());
    }

    drop(event: CdkDragDrop<FormGroup[]>): void {
        if (event.previousIndex !== event.currentIndex) {
            // Get the actual FormArray (not the sorted view)
            const talkgroupsArray = this.form.get('talkgroups') as FormArray | null;
            
            if (!talkgroupsArray) {
                return;
            }

            // Move items in the visual sorted array
            moveItemInArray(event.container.data, event.previousIndex, event.currentIndex);

            // Update order values to match new positions
            event.container.data.forEach((dat, idx) => dat.get('order')?.setValue(idx + 1, { emitEvent: false }));

            // CRITICAL: Reorder the actual FormArray to match the new sorted order
            // This ensures getRawValue() returns talkgroups in the correct order
            const reorderedControls = event.container.data.slice();
            talkgroupsArray.clear({ emitEvent: false });
            reorderedControls.forEach(control => {
                talkgroupsArray.push(control, { emitEvent: false });
            });

            this.form.markAsDirty();
        }
    }

    removeSite(index: number): void {
        const sites = this.form.get('sites') as FormArray | null;

        sites?.removeAt(index);

        sites?.markAsDirty();
    }

    removeTalkgroup(index: number): void {
        const talkgroups = this.form.get('talkgroups') as FormArray | null;

        talkgroups?.removeAt(index);

        talkgroups?.markAsDirty();
    }

    removeUnit(index: number): void {
        const units = this.form.get('units') as FormArray | null;

        units?.removeAt(index);

        units?.markAsDirty();
    }

    // Bulk selection methods
    toggleTalkgroupSelection(index: number): void {
        if (this.selectedTalkgroupIndices.has(index)) {
            this.selectedTalkgroupIndices.delete(index);
        } else {
            this.selectedTalkgroupIndices.add(index);
        }
    }

    isTalkgroupSelected(index: number): boolean {
        return this.selectedTalkgroupIndices.has(index);
    }

    selectAllTalkgroups(): void {
        this.selectedTalkgroupIndices.clear();
        this.talkgroups.forEach((_, index) => {
            this.selectedTalkgroupIndices.add(index);
        });
    }

    unselectAllTalkgroups(): void {
        this.selectedTalkgroupIndices.clear();
    }

    bulkAssignGroup(): void {
        if (this.bulkAssignGroupId === null || this.selectedTalkgroupIndices.size === 0) {
            return;
        }

        this.selectedTalkgroupIndices.forEach(index => {
            const talkgroup = this.talkgroups[index];
            const groupIds = talkgroup.get('groupIds')?.value || [];
            
            // Add the group if it's not already assigned
            if (!groupIds.includes(this.bulkAssignGroupId)) {
                const newGroupIds = [...groupIds, this.bulkAssignGroupId];
                talkgroup.get('groupIds')?.setValue(newGroupIds);
                talkgroup.markAsDirty();
            }
        });

        this.form.markAsDirty();
        this.unselectAllTalkgroups();
        this.bulkAssignGroupId = null;
    }

    bulkAssignTag(): void {
        if (this.bulkAssignTagId === null || this.selectedTalkgroupIndices.size === 0) {
            return;
        }

        this.selectedTalkgroupIndices.forEach(index => {
            const talkgroup = this.talkgroups[index];
            talkgroup.get('tagId')?.setValue(this.bulkAssignTagId);
            talkgroup.markAsDirty();
        });

        this.form.markAsDirty();
        this.unselectAllTalkgroups();
        this.bulkAssignTagId = null;
    }

    bulkRemoveGroup(): void {
        if (this.bulkAssignGroupId === null || this.selectedTalkgroupIndices.size === 0) {
            return;
        }

        this.selectedTalkgroupIndices.forEach(index => {
            const talkgroup = this.talkgroups[index];
            const groupIds = talkgroup.get('groupIds')?.value || [];
            
            // Remove the group if it's assigned
            const newGroupIds = groupIds.filter((id: number) => id !== this.bulkAssignGroupId);
            talkgroup.get('groupIds')?.setValue(newGroupIds);
            talkgroup.markAsDirty();
        });

        this.form.markAsDirty();
        this.unselectAllTalkgroups();
        this.bulkAssignGroupId = null;
    }

    sortTalkgroupsAlphabetically(): void {
        const talkgroupsArray = this.form.get('talkgroups') as FormArray | null;
        
        if (!talkgroupsArray || talkgroupsArray.length === 0) {
            return;
        }

        // Get all talkgroup controls and sort them alphabetically by label
        const sortedControls = talkgroupsArray.controls.slice().sort((a, b) => {
            const labelA = (a.get('label')?.value || '').toString().trim().toLowerCase();
            const labelB = (b.get('label')?.value || '').toString().trim().toLowerCase();
            return labelA.localeCompare(labelB);
        });

        // Update order values based on new alphabetical positions
        sortedControls.forEach((control, idx) => {
            control.get('order')?.setValue(idx + 1, { emitEvent: false });
        });

        // Rebuild the FormArray to match the new sorted order
        talkgroupsArray.clear({ emitEvent: false });
        sortedControls.forEach(control => {
            talkgroupsArray.push(control, { emitEvent: false });
        });

        this.form.markAsDirty();
        this.unselectAllTalkgroups();
    }

    getTalkgroupsErrorSummary(): string {
        const talkgroupsArray = this.form.get('talkgroups') as FormArray | null;
        if (!talkgroupsArray) return 'Invalid talkgroups';
        
        const invalidCount = talkgroupsArray.controls.filter(c => c.invalid).length;
        return `${invalidCount} invalid talkgroup${invalidCount !== 1 ? 's' : ''}`;
    }

    getTalkgroupErrors(talkgroupForm: FormGroup): string {
        const errors: string[] = [];
        
        if (talkgroupForm.get('talkgroupRef')?.hasError('required')) {
            errors.push('ID required');
        } else if (talkgroupForm.get('talkgroupRef')?.hasError('duplicate')) {
            errors.push('Duplicate ID');
        } else if (talkgroupForm.get('talkgroupRef')?.hasError('min')) {
            errors.push('Invalid ID');
        }
        
        if (talkgroupForm.get('label')?.hasError('required')) {
            errors.push('Label required');
        }
        
        if (talkgroupForm.get('name')?.hasError('required')) {
            errors.push('Name required');
        }

        if (talkgroupForm.get('groupIds')?.hasError('required')) {
            errors.push('Group required');
        }

        if (talkgroupForm.get('tagId')?.hasError('required')) {
            errors.push('Tag required');
        }

        return errors.join(', ');
    }
}
