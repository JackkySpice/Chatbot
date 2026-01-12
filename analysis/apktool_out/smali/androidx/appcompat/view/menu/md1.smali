.class public final Landroidx/appcompat/view/menu/md1;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final a:I

.field public final b:Landroidx/appcompat/view/menu/df;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/df;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {p1}, Landroidx/appcompat/view/menu/ij0;->i(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Landroidx/appcompat/view/menu/md1;->b:Landroidx/appcompat/view/menu/df;

    iput p2, p0, Landroidx/appcompat/view/menu/md1;->a:I

    return-void
.end method


# virtual methods
.method public final a()I
    .locals 1

    iget v0, p0, Landroidx/appcompat/view/menu/md1;->a:I

    return v0
.end method

.method public final b()Landroidx/appcompat/view/menu/df;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/md1;->b:Landroidx/appcompat/view/menu/df;

    return-object v0
.end method
