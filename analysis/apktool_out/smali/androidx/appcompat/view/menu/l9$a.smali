.class public final Landroidx/appcompat/view/menu/l9$a;
.super Landroidx/appcompat/view/menu/yg;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/l9;->e(Landroidx/appcompat/view/menu/ck0;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation


# instance fields
.field public p:Ljava/lang/Object;

.field public synthetic q:Ljava/lang/Object;

.field public final synthetic r:Landroidx/appcompat/view/menu/l9;

.field public s:I


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/l9;Landroidx/appcompat/view/menu/wg;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/l9$a;->r:Landroidx/appcompat/view/menu/l9;

    invoke-direct {p0, p2}, Landroidx/appcompat/view/menu/yg;-><init>(Landroidx/appcompat/view/menu/wg;)V

    return-void
.end method


# virtual methods
.method public final k(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iput-object p1, p0, Landroidx/appcompat/view/menu/l9$a;->q:Ljava/lang/Object;

    iget p1, p0, Landroidx/appcompat/view/menu/l9$a;->s:I

    const/high16 v0, -0x80000000

    or-int/2addr p1, v0

    iput p1, p0, Landroidx/appcompat/view/menu/l9$a;->s:I

    iget-object p1, p0, Landroidx/appcompat/view/menu/l9$a;->r:Landroidx/appcompat/view/menu/l9;

    const/4 v0, 0x0

    invoke-virtual {p1, v0, p0}, Landroidx/appcompat/view/menu/l9;->e(Landroidx/appcompat/view/menu/ck0;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
