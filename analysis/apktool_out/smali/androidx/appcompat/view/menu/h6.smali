.class public final Landroidx/appcompat/view/menu/h6;
.super Landroidx/appcompat/view/menu/js0;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/h6$b;
    }
.end annotation


# instance fields
.field public final a:Landroidx/appcompat/view/menu/z11;

.field public final b:Ljava/lang/String;

.field public final c:Landroidx/appcompat/view/menu/vo;

.field public final d:Landroidx/appcompat/view/menu/n11;

.field public final e:Landroidx/appcompat/view/menu/ko;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/z11;Ljava/lang/String;Landroidx/appcompat/view/menu/vo;Landroidx/appcompat/view/menu/n11;Landroidx/appcompat/view/menu/ko;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Landroidx/appcompat/view/menu/js0;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/h6;->a:Landroidx/appcompat/view/menu/z11;

    iput-object p2, p0, Landroidx/appcompat/view/menu/h6;->b:Ljava/lang/String;

    iput-object p3, p0, Landroidx/appcompat/view/menu/h6;->c:Landroidx/appcompat/view/menu/vo;

    iput-object p4, p0, Landroidx/appcompat/view/menu/h6;->d:Landroidx/appcompat/view/menu/n11;

    iput-object p5, p0, Landroidx/appcompat/view/menu/h6;->e:Landroidx/appcompat/view/menu/ko;

    return-void
.end method

.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/z11;Ljava/lang/String;Landroidx/appcompat/view/menu/vo;Landroidx/appcompat/view/menu/n11;Landroidx/appcompat/view/menu/ko;Landroidx/appcompat/view/menu/h6$a;)V
    .locals 0

    .line 1
    invoke-direct/range {p0 .. p5}, Landroidx/appcompat/view/menu/h6;-><init>(Landroidx/appcompat/view/menu/z11;Ljava/lang/String;Landroidx/appcompat/view/menu/vo;Landroidx/appcompat/view/menu/n11;Landroidx/appcompat/view/menu/ko;)V

    return-void
.end method


# virtual methods
.method public b()Landroidx/appcompat/view/menu/ko;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/h6;->e:Landroidx/appcompat/view/menu/ko;

    return-object v0
.end method

.method public c()Landroidx/appcompat/view/menu/vo;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/h6;->c:Landroidx/appcompat/view/menu/vo;

    return-object v0
.end method

.method public e()Landroidx/appcompat/view/menu/n11;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/h6;->d:Landroidx/appcompat/view/menu/n11;

    return-object v0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    const/4 v0, 0x1

    if-ne p1, p0, :cond_0

    return v0

    :cond_0
    instance-of v1, p1, Landroidx/appcompat/view/menu/js0;

    const/4 v2, 0x0

    if-eqz v1, :cond_2

    check-cast p1, Landroidx/appcompat/view/menu/js0;

    iget-object v1, p0, Landroidx/appcompat/view/menu/h6;->a:Landroidx/appcompat/view/menu/z11;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/js0;->f()Landroidx/appcompat/view/menu/z11;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    iget-object v1, p0, Landroidx/appcompat/view/menu/h6;->b:Ljava/lang/String;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/js0;->g()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    iget-object v1, p0, Landroidx/appcompat/view/menu/h6;->c:Landroidx/appcompat/view/menu/vo;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/js0;->c()Landroidx/appcompat/view/menu/vo;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    iget-object v1, p0, Landroidx/appcompat/view/menu/h6;->d:Landroidx/appcompat/view/menu/n11;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/js0;->e()Landroidx/appcompat/view/menu/n11;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    iget-object v1, p0, Landroidx/appcompat/view/menu/h6;->e:Landroidx/appcompat/view/menu/ko;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/js0;->b()Landroidx/appcompat/view/menu/ko;

    move-result-object p1

    invoke-virtual {v1, p1}, Landroidx/appcompat/view/menu/ko;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_1

    goto :goto_0

    :cond_1
    move v0, v2

    :goto_0
    return v0

    :cond_2
    return v2
.end method

.method public f()Landroidx/appcompat/view/menu/z11;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/h6;->a:Landroidx/appcompat/view/menu/z11;

    return-object v0
.end method

.method public g()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/h6;->b:Ljava/lang/String;

    return-object v0
.end method

.method public hashCode()I
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/h6;->a:Landroidx/appcompat/view/menu/z11;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    const v1, 0xf4243

    xor-int/2addr v0, v1

    mul-int/2addr v0, v1

    iget-object v2, p0, Landroidx/appcompat/view/menu/h6;->b:Ljava/lang/String;

    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    move-result v2

    xor-int/2addr v0, v2

    mul-int/2addr v0, v1

    iget-object v2, p0, Landroidx/appcompat/view/menu/h6;->c:Landroidx/appcompat/view/menu/vo;

    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    move-result v2

    xor-int/2addr v0, v2

    mul-int/2addr v0, v1

    iget-object v2, p0, Landroidx/appcompat/view/menu/h6;->d:Landroidx/appcompat/view/menu/n11;

    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    move-result v2

    xor-int/2addr v0, v2

    mul-int/2addr v0, v1

    iget-object v1, p0, Landroidx/appcompat/view/menu/h6;->e:Landroidx/appcompat/view/menu/ko;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/ko;->hashCode()I

    move-result v1

    xor-int/2addr v0, v1

    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "SendRequest{transportContext="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Landroidx/appcompat/view/menu/h6;->a:Landroidx/appcompat/view/menu/z11;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", transportName="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Landroidx/appcompat/view/menu/h6;->b:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ", event="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Landroidx/appcompat/view/menu/h6;->c:Landroidx/appcompat/view/menu/vo;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", transformer="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Landroidx/appcompat/view/menu/h6;->d:Landroidx/appcompat/view/menu/n11;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", encoding="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Landroidx/appcompat/view/menu/h6;->e:Landroidx/appcompat/view/menu/ko;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, "}"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
