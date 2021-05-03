import React, { useState } from "react";
import { useForm } from "react-hook-form";
import styled from "styled-components";
import { Button } from "../components/Button";
import { TextInput } from "../components/TextInput";
import { Signature } from "./Signature";

const Wrapper = styled.div`
  width: 700px;
  display: flex;
  flex: 0 0 auto;
`;

const Content = styled.div`
  display: flex;
  flex: 1 1 auto;
  flex-direction: column;
`;

const Row = styled.div`
  display: flex;
  flex-direction: row;
  flex: 1 1 auto;
`;

const PrivateKeyTextInput = styled(TextInput)`
  margin: 0px 5px 10px 0px;
`;

const MessageTextInput = styled(TextInput)`
  margin: 0px 0px 10px 5px;
`;

export const Form = () => {
  const [signature, setSignature] = useState<String>("");
  const [resultVerify, setResultVerify] = useState<String>("");
  const [pubkey, setPubkey] = useState<String>("");

  const {
    register,
    handleSubmit,
    formState: { isDirty },
  } = useForm();

  const onSubmit = handleSubmit(async (data) => {
    const promise = await import("elliptic-curve");
    const result = promise.sign(data.privateKey, data.message);
    const resultPubkey = promise.get_pubkey(data.privateKey);

    const resultVerify = promise.verify(resultPubkey, data.message, result);

    setPubkey(resultPubkey);
    setSignature(result);
    setResultVerify(resultVerify);
  });

  return (
    <form onSubmit={onSubmit}>
      <Wrapper>
        <Content>
          <Row>
            <PrivateKeyTextInput
              {...register("privateKey")}
              placeholder='Please enter your private key here'
              testId='private-key'
            />
            <MessageTextInput
              {...register("message")}
              placeholder='Please enter your message here'
              testId='message'
            />
          </Row>
          <Signature>{signature}</Signature>
          <Row>
            <Button onClick={onSubmit} testId='submit' disabled={!isDirty}>
              Sign
            </Button>
          </Row>
          <div>
            Result pubkey: <br />
            {pubkey}
          </div>
          <div>
            Result verify: <br />
            {resultVerify}
          </div>
        </Content>
      </Wrapper>
    </form>
  );
};
