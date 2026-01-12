.class public final Landroidx/appcompat/view/menu/nr1$a;
.super Landroidx/appcompat/view/menu/m02$b;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/w32;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/nr1;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-static {}, Landroidx/appcompat/view/menu/nr1;->O()Landroidx/appcompat/view/menu/nr1;

    move-result-object v0

    invoke-direct {p0, v0}, Landroidx/appcompat/view/menu/m02$b;-><init>(Landroidx/appcompat/view/menu/m02;)V

    return-void
.end method

.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/jr1;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Landroidx/appcompat/view/menu/nr1$a;-><init>()V

    return-void
.end method


# virtual methods
.method public final r()I
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/m02$b;->n:Landroidx/appcompat/view/menu/m02;

    check-cast v0, Landroidx/appcompat/view/menu/nr1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/nr1;->K()I

    move-result v0

    return v0
.end method

.method public final s(I)Landroidx/appcompat/view/menu/mr1;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/m02$b;->n:Landroidx/appcompat/view/menu/m02;

    check-cast v0, Landroidx/appcompat/view/menu/nr1;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/nr1;->G(I)Landroidx/appcompat/view/menu/mr1;

    move-result-object p1

    return-object p1
.end method

.method public final t(ILandroidx/appcompat/view/menu/mr1$a;)Landroidx/appcompat/view/menu/nr1$a;
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/m02$b;->n()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/m02$b;->n:Landroidx/appcompat/view/menu/m02;

    check-cast v0, Landroidx/appcompat/view/menu/nr1;

    invoke-virtual {p2}, Landroidx/appcompat/view/menu/m02$b;->j()Landroidx/appcompat/view/menu/s32;

    move-result-object p2

    check-cast p2, Landroidx/appcompat/view/menu/m02;

    check-cast p2, Landroidx/appcompat/view/menu/mr1;

    invoke-static {v0, p1, p2}, Landroidx/appcompat/view/menu/nr1;->J(Landroidx/appcompat/view/menu/nr1;ILandroidx/appcompat/view/menu/mr1;)V

    return-object p0
.end method

.method public final u()Landroidx/appcompat/view/menu/nr1$a;
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/m02$b;->n()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/m02$b;->n:Landroidx/appcompat/view/menu/m02;

    check-cast v0, Landroidx/appcompat/view/menu/nr1;

    invoke-static {v0}, Landroidx/appcompat/view/menu/nr1;->I(Landroidx/appcompat/view/menu/nr1;)V

    return-object p0
.end method

.method public final v()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/m02$b;->n:Landroidx/appcompat/view/menu/m02;

    check-cast v0, Landroidx/appcompat/view/menu/nr1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/nr1;->T()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final w()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/m02$b;->n:Landroidx/appcompat/view/menu/m02;

    check-cast v0, Landroidx/appcompat/view/menu/nr1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/nr1;->U()Ljava/util/List;

    move-result-object v0

    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public final x()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/m02$b;->n:Landroidx/appcompat/view/menu/m02;

    check-cast v0, Landroidx/appcompat/view/menu/nr1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/nr1;->V()Ljava/util/List;

    move-result-object v0

    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    return-object v0
.end method
