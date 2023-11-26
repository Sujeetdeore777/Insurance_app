// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

contract HealthManagement {
    struct GeneralMedicine {
        string record_id;
        uint256 timestamp;
        string gender;
        uint16 currentWeight;
        string currentHeight;
        string analysis;
        string bloodDetails;
        string bp;
        string bmi;
        uint8 age;
        bool isDiabetic;
        bool isAllergic;
    }
    struct MedicalRecord {
        GeneralMedicine[] records;
        uint256 recordCount;
    }
    mapping(string => MedicalRecord) private patientRecords;
    mapping(string => mapping(string => uint256)) private recordIdToIndex;
    event RecordCreated(
        string id,
        string record_id,
        uint256 recordIndex,
        uint256 timestamp,
        string gender,
        uint16 currentWeight,
        string currentHeight,
        string analysis,
        string bloodDetails,
        string bp,
        string bmi,
        uint8 age,
        bool isDiabetic,
        bool isAllergic
    );
    event RecordUpdated(
        string id,
        string record_id,
        uint256 recordIndex,
        string gender,
        uint16 currentWeight,
        string currentHeight,
        string analysis,
        string bloodDetails,
        string bp,
        string bmi,
        uint8 age,
        bool isDiabetic,
        bool isAllergic
    );
    event RecordDeleted(string id, uint256 recordIndex);

    function createGeneralMedicineRecord(
        string memory id,
        string memory record_id,
        string memory gender,
        uint16 currentWeight,
        string memory currentHeight,
        string memory analysis,
        string memory bloodDetails,
        string memory bp,
        string memory bmi,
        uint8 age,
        bool isDiabetic,
        bool isAllergic
    ) external {
        require(bytes(id).length > 0, "ID cannot be empty");
        require(currentWeight > 0, "Weight must be greater than zero");
        require(
            bytes(currentHeight).length > 0,
            "Height must be greater than zero"
        );
        require(bytes(bmi).length > 0, "BMI must be greater than zero");
        require(age > 0, "Age must be greater than zero");
        GeneralMedicine memory record;
        record.age = age;
        record.record_id = record_id;
        record.timestamp = block.timestamp;
        record.analysis = analysis;
        record.bloodDetails = bloodDetails;
        record.bmi = bmi;
        record.bp = bp;
        record.currentHeight = currentHeight;
        record.currentWeight = currentWeight;
        record.gender = gender;
        record.isDiabetic = isDiabetic;
        record.isAllergic = isAllergic;
        MedicalRecord storage patientRecord = patientRecords[id];
        patientRecord.records.push(record);
        recordIdToIndex[id][record_id] = patientRecord.records.length - 1;
        patientRecord.recordCount = patientRecord.records.length;
        uint256 recordIndex = patientRecord.records.length - 1;
        emit RecordCreated(
            id,
            record_id,
            recordIndex,
            block.timestamp,
            gender,
            currentWeight,
            currentHeight,
            analysis,
            bloodDetails,
            bp,
            bmi,
            age,
            isDiabetic,
            isAllergic
        );
    }

    function getGeneralMedicineRecords(
        string memory id
    ) external view returns (GeneralMedicine[] memory) {
        MedicalRecord storage patientRecord = patientRecords[id];
        return patientRecord.records;
    }

    function getRecordByRecordId(
        string memory id,
        string memory record_id
    ) external view returns (GeneralMedicine memory, uint256) {
        uint256 index = recordIdToIndex[id][record_id];
        require(index < patientRecords[id].records.length, "Record not found");
        GeneralMedicine memory record = patientRecords[id].records[index];
        return (record, record.timestamp);
    }

    function updateGeneralMedicineRecord(
        string memory id,
        string memory record_id,
        uint16 currentWeight,
        string memory currentHeight,
        string memory analysis,
        string memory bloodDetails,
        string memory bp,
        string memory bmi,
        uint8 age,
        bool isDiabetic,
        bool isAllergic
    ) external {
        MedicalRecord storage patientRecord = patientRecords[id];
        uint256 recordIndex = recordIdToIndex[id][record_id];
        require(recordIndex < patientRecord.records.length, "Record not found");
        GeneralMedicine storage record = patientRecord.records[recordIndex];
        require(currentWeight > 0, "Weight must be greater than zero");
        require(
            bytes(currentHeight).length > 0,
            "Height must be greater than zero"
        );
        require(bytes(bmi).length > 0, "BMI must be greater than zero");
        require(age > 0, "Age must be greater than zero");
        // Update the fields
        record.currentWeight = currentWeight;
        record.currentHeight = currentHeight;
        record.analysis = analysis;
        record.bloodDetails = bloodDetails;
        record.bp = bp;
        record.bmi = bmi;
        record.age = age;
        record.isDiabetic = isDiabetic;
        record.isAllergic = isAllergic;
        emit RecordUpdated(
            id,
            record_id,
            recordIndex,
            record.gender,
            currentWeight,
            currentHeight,
            analysis,
            bloodDetails,
            bp,
            bmi,
            age,
            isDiabetic,
            isAllergic
        );
    }

    function deleteGeneralMedicineRecord(
        string memory id,
        string memory record_id
    ) external {
        MedicalRecord storage patientRecord = patientRecords[id];
        uint256 recordIndex = recordIdToIndex[id][record_id];
        require(recordIndex < patientRecord.records.length, "Record not found");
        delete patientRecord.records[recordIndex];
        patientRecord.recordCount = patientRecord.records.length;
        emit RecordDeleted(id, recordIndex);
    }
}
