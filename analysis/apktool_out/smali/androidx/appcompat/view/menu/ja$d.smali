.class public Landroidx/appcompat/view/menu/ja$d;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/ja;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "d"
.end annotation


# instance fields
.field public final a:Landroidx/appcompat/view/menu/qc0;

.field public final b:Landroidx/appcompat/view/menu/jc0;

.field public final c:I


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/qc0;Landroidx/appcompat/view/menu/jc0;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/ja$d;->a:Landroidx/appcompat/view/menu/qc0;

    iput-object p2, p0, Landroidx/appcompat/view/menu/ja$d;->b:Landroidx/appcompat/view/menu/jc0;

    iput p3, p0, Landroidx/appcompat/view/menu/ja$d;->c:I

    return-void
.end method


# virtual methods
.method public a()Landroid/widget/ListView;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ja$d;->a:Landroidx/appcompat/view/menu/qc0;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/e90;->d()Landroid/widget/ListView;

    move-result-object v0

    return-object v0
.end method
