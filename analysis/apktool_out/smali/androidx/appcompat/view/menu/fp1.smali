.class public final Landroidx/appcompat/view/menu/fp1;
.super Landroidx/appcompat/view/menu/in1$a;
.source "SourceFile"


# instance fields
.field public final synthetic q:I

.field public final synthetic r:Ljava/lang/String;

.field public final synthetic s:Ljava/lang/Object;

.field public final synthetic t:Ljava/lang/Object;

.field public final synthetic u:Ljava/lang/Object;

.field public final synthetic v:Landroidx/appcompat/view/menu/in1;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/in1;ZILjava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/fp1;->v:Landroidx/appcompat/view/menu/in1;

    const/4 p2, 0x5

    iput p2, p0, Landroidx/appcompat/view/menu/fp1;->q:I

    iput-object p4, p0, Landroidx/appcompat/view/menu/fp1;->r:Ljava/lang/String;

    iput-object p5, p0, Landroidx/appcompat/view/menu/fp1;->s:Ljava/lang/Object;

    const/4 p2, 0x0

    iput-object p2, p0, Landroidx/appcompat/view/menu/fp1;->t:Ljava/lang/Object;

    iput-object p2, p0, Landroidx/appcompat/view/menu/fp1;->u:Ljava/lang/Object;

    const/4 p2, 0x0

    invoke-direct {p0, p1, p2}, Landroidx/appcompat/view/menu/in1$a;-><init>(Landroidx/appcompat/view/menu/in1;Z)V

    return-void
.end method


# virtual methods
.method public final a()V
    .locals 7

    iget-object v0, p0, Landroidx/appcompat/view/menu/fp1;->v:Landroidx/appcompat/view/menu/in1;

    invoke-static {v0}, Landroidx/appcompat/view/menu/in1;->d(Landroidx/appcompat/view/menu/in1;)Landroidx/appcompat/view/menu/bm1;

    move-result-object v0

    invoke-static {v0}, Landroidx/appcompat/view/menu/ij0;->i(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Landroidx/appcompat/view/menu/bm1;

    iget v2, p0, Landroidx/appcompat/view/menu/fp1;->q:I

    iget-object v3, p0, Landroidx/appcompat/view/menu/fp1;->r:Ljava/lang/String;

    iget-object v0, p0, Landroidx/appcompat/view/menu/fp1;->s:Ljava/lang/Object;

    invoke-static {v0}, Landroidx/appcompat/view/menu/rf0;->k(Ljava/lang/Object;)Landroidx/appcompat/view/menu/d20;

    move-result-object v4

    const/4 v0, 0x0

    invoke-static {v0}, Landroidx/appcompat/view/menu/rf0;->k(Ljava/lang/Object;)Landroidx/appcompat/view/menu/d20;

    move-result-object v5

    invoke-static {v0}, Landroidx/appcompat/view/menu/rf0;->k(Ljava/lang/Object;)Landroidx/appcompat/view/menu/d20;

    move-result-object v6

    invoke-interface/range {v1 .. v6}, Landroidx/appcompat/view/menu/bm1;->logHealthData(ILjava/lang/String;Landroidx/appcompat/view/menu/d20;Landroidx/appcompat/view/menu/d20;Landroidx/appcompat/view/menu/d20;)V

    return-void
.end method
