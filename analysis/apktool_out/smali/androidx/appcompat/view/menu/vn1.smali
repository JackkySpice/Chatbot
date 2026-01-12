.class public final Landroidx/appcompat/view/menu/vn1;
.super Landroidx/appcompat/view/menu/in1$a;
.source "SourceFile"


# instance fields
.field public final synthetic q:Landroid/app/Activity;

.field public final synthetic r:Ljava/lang/String;

.field public final synthetic s:Ljava/lang/String;

.field public final synthetic t:Landroidx/appcompat/view/menu/in1;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/in1;Landroid/app/Activity;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/vn1;->t:Landroidx/appcompat/view/menu/in1;

    iput-object p2, p0, Landroidx/appcompat/view/menu/vn1;->q:Landroid/app/Activity;

    iput-object p3, p0, Landroidx/appcompat/view/menu/vn1;->r:Ljava/lang/String;

    iput-object p4, p0, Landroidx/appcompat/view/menu/vn1;->s:Ljava/lang/String;

    invoke-direct {p0, p1}, Landroidx/appcompat/view/menu/in1$a;-><init>(Landroidx/appcompat/view/menu/in1;)V

    return-void
.end method


# virtual methods
.method public final a()V
    .locals 7

    iget-object v0, p0, Landroidx/appcompat/view/menu/vn1;->t:Landroidx/appcompat/view/menu/in1;

    invoke-static {v0}, Landroidx/appcompat/view/menu/in1;->d(Landroidx/appcompat/view/menu/in1;)Landroidx/appcompat/view/menu/bm1;

    move-result-object v0

    invoke-static {v0}, Landroidx/appcompat/view/menu/ij0;->i(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Landroidx/appcompat/view/menu/bm1;

    iget-object v0, p0, Landroidx/appcompat/view/menu/vn1;->q:Landroid/app/Activity;

    invoke-static {v0}, Landroidx/appcompat/view/menu/rf0;->k(Ljava/lang/Object;)Landroidx/appcompat/view/menu/d20;

    move-result-object v2

    iget-object v3, p0, Landroidx/appcompat/view/menu/vn1;->r:Ljava/lang/String;

    iget-object v4, p0, Landroidx/appcompat/view/menu/vn1;->s:Ljava/lang/String;

    iget-wide v5, p0, Landroidx/appcompat/view/menu/in1$a;->m:J

    invoke-interface/range {v1 .. v6}, Landroidx/appcompat/view/menu/bm1;->setCurrentScreen(Landroidx/appcompat/view/menu/d20;Ljava/lang/String;Ljava/lang/String;J)V

    return-void
.end method
